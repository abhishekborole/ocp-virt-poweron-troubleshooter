"""Regression tests use mocked API responses; they never connect to infrastructure."""
import argparse
from datetime import datetime, timedelta, timezone
import io
import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import troubleshoot as t


class TestCase(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='ocp-virt-diagnostic-test-')
        self.base = Path(self.temporary.name).resolve()
        self.assertEqual(self.base.parent, Path(tempfile.gettempdir()).resolve())
        self.addCleanup(self.temporary.cleanup)
        self.bundle = t.Bundle(self.base/'bundle')
        self.args = t.parser().parse_args(['--context','lab-context','--namespace','apps','--vm','database'])

    def collector(self):
        collector = t.Collector(self.args, self.bundle, None)
        collector.vm = {'metadata':{'uid':'vm-uid-001','name':'database'},'spec':{'runStrategy':'Always'}}
        return collector


class UtilityTests(TestCase):
    def test_duration(self):
        self.assertEqual(t.duration('1h30m'), 5400)
        for value in ('0m','-1h','infinite','10','1d'):
            with self.assertRaises(argparse.ArgumentTypeError): t.duration(value)

    def test_output_is_never_overwritten(self):
        with self.assertRaises(FileExistsError): t.Bundle(self.bundle.root)

    def test_output_cannot_escape_bundle(self):
        with self.assertRaises(ValueError): self.bundle.write('../escape.txt','text','test')

    def test_sanitized_names_do_not_collide(self):
        self.assertNotEqual(t.safe_name('a/b'),t.safe_name('a_b'))

    def test_common_credentials_and_inline_userdata_redacted(self):
        value = {'spec':{'volumes':[{'cloudInitNoCloud':{'userData':'private-userdata'}}],
                         'containers':[{'env':[{'name':'LICENSE','value':'private-env'}]}]},
                 'metadata':{'annotations':{'kubectl.kubernetes.io/last-applied-configuration':'private-annotation'}}}
        rendered = json.dumps(t.sanitize(value))
        for secret in ('private-userdata','private-env','private-annotation'): self.assertNotIn(secret,rendered)
        self.assertNotIn('abcdef-token',t.redact_text('Authorization: Bearer abcdef-token'))

    def test_secret_objects_never_export_data(self):
        rendered = json.dumps(t.sanitize({'kind':'Secret','metadata':{'name':'credential'},'data':{'password':'do-not-export'}}))
        self.assertNotIn('do-not-export',rendered)

    def test_pod_dependency_matching(self):
        self.assertTrue(t.related_pod({'metadata':{'ownerReferences':[{'uid':'vmi-001'}]}},{'vmi-001'},set()))
        self.assertTrue(t.related_pod({'spec':{'volumes':[{'persistentVolumeClaim':{'claimName':'disk'}}]}},set(),{'disk'}))
        self.assertFalse(t.related_pod({'metadata':{'name':'unrelated'}},{'vmi-001'},{'disk'}))

    def test_csi_and_controller_discovery(self):
        self.assertEqual(t.component({'metadata':{'name':'virt-controller-abc'}},set(),set()),'virt-controller')
        pod={'metadata':{'name':'plugin','namespace':'storage'},'spec':{'containers':[{'name':'provisioner','image':'registry/csi-provisioner:v1'}]}}
        self.assertEqual(t.component(pod,set(),set()),'csi-discovered')
        self.assertEqual(t.component({'metadata':{'namespace':'custom-array','name':'unusual-driver'}},set(),{'custom-array'}),'csi-explicit-namespace')

    def test_stale_and_recreated_object_events_excluded(self):
        cutoff = datetime.now(timezone.utc)-timedelta(hours=1)
        def event(uid,timestamp): return {'involvedObject':{'uid':uid,'namespace':'apps','kind':'VirtualMachine','name':'database'},'lastTimestamp':timestamp}
        current=datetime.now(timezone.utc).isoformat()
        old=(cutoff-timedelta(hours=1)).isoformat()
        selected=t.filter_events([event('current',current),event('old-instance',current),event('current',old)],{'current'},{('apps','VirtualMachine','database')},cutoff)
        self.assertEqual(len(selected),1)


class DiagnosisTests(TestCase):
    def test_unrelated_shared_errors_are_not_root_causes(self):
        collector=self.collector()
        self.bundle.write('logs/csi.log','FailedAttachVolume for other-tenant-volume','container-log','shared')
        findings,ignored=t.diagnose(collector)
        self.assertEqual(findings,[]); self.assertEqual(ignored,1)

    def test_correlated_csi_error_has_file_and_line(self):
        collector=self.collector();collector.identifiers={'pvc-uid-12345'}
        self.bundle.write('logs/csi.log','info\nFailedAttachVolume pvc-uid-12345','container-log','shared')
        findings,_=t.diagnose(collector)
        finding=next(row for row in findings if row['id']=='storage-attach')
        self.assertEqual(finding['confidence'],'medium')
        self.assertEqual(finding['evidence'][0]['line'],2)
        self.assertEqual(finding['evidence'][0]['artifact'],'logs/csi.log')

    def test_launcher_disk_lock_is_direct_evidence(self):
        collector=self.collector()
        self.bundle.write('logs/compute.log','Failed to get write lock for disk.img','container-log','vm')
        findings,_=t.diagnose(collector)
        self.assertEqual(findings[0]['id'],'disk-image');self.assertEqual(findings[0]['confidence'],'high')

    def test_halted_vm_is_reported(self):
        collector=self.collector();collector.vm['spec']['runStrategy']='Halted'
        findings,_=t.diagnose(collector)
        self.assertIn('not-requested',{row['id'] for row in findings})

    def test_waiting_for_consumer_is_not_called_backend_failure(self):
        collector=self.collector()
        collector.pvcs=[{'metadata':{'name':'disk'},'status':{'phase':'Pending'}}]
        findings,_=t.diagnose(collector)
        self.assertEqual(findings[0]['confidence'],'medium')
        self.assertIn('WaitForFirstConsumer',findings[0]['next_check'])

    def test_pod_scheduling_condition_is_evidence_without_events(self):
        collector=self.collector()
        collector.pods=[({'metadata':{'name':'launcher','namespace':'apps'},'status':{'conditions':[{'type':'PodScheduled','status':'False','reason':'Unschedulable','message':'Insufficient memory'}]}},'workload','vm')]
        findings,_=t.diagnose(collector)
        self.assertIn('capacity',{row['id'] for row in findings})

    def test_node_pressure(self):
        collector=self.collector()
        collector.nodes=[{'metadata':{'name':'worker'},'status':{'conditions':[{'type':'DiskPressure','status':'True'}]}}]
        findings,_=t.diagnose(collector)
        self.assertIn('node-health',{row['id'] for row in findings})

    def test_readiness_requires_all_discovered_replicas_unready(self):
        collector=self.collector()
        def pod(name,ready):return {'metadata':{'namespace':'openshift-cnv','name':name},'status':{'conditions':[{'type':'Ready','status':ready}]}}
        collector.pods=[(pod('controller-1','False'),'virt-controller','shared'),(pod('controller-2','True'),'virt-controller','shared')]
        findings,_=t.diagnose(collector)
        self.assertNotIn('component-virt-controller',{row['id'] for row in findings})

    def test_absence_of_signatures_is_inconclusive(self):
        collector=self.collector()
        result=t.report(collector)
        self.assertEqual(result['findings'],[])
        self.assertIn('inconclusive',(self.bundle.root/'summary.md').read_text())

    def test_short_names_do_not_match_unrelated_text(self):
        self.assertFalse(t.correlated('db connection error in other namespace',set(),'apps','db'))
        self.assertTrue(t.correlated('namespace=apps vm=db',set(),'apps','db'))


class TransportTests(TestCase):
    @patch('troubleshoot.shutil.which',return_value='oc')
    @patch('troubleshoot.subprocess.run')
    def test_explicit_context_namespace_and_read_only(self,run,which):
        run.return_value=SimpleNamespace(returncode=0,stdout='{"items":[]}',stderr='')
        oc=t.OC('chosen-context',self.bundle)
        oc.get('pods',namespace='only-namespace')
        arguments,options=run.call_args
        self.assertIn('chosen-context',arguments[0]);self.assertIn('only-namespace',arguments[0]);self.assertIn('get',arguments[0])
        self.assertFalse(options['shell']);self.assertLessEqual(options['timeout'],40)

    @patch('troubleshoot.shutil.which',return_value='oc')
    @patch('troubleshoot.subprocess.run')
    def test_rbac_denial_is_a_gap_not_healthy(self,run,which):
        run.return_value=SimpleNamespace(returncode=1,stdout='',stderr='Forbidden: cannot get pods/log')
        oc=t.OC('context',self.bundle)
        self.assertIsNone(oc.get('pods'))
        self.assertEqual(self.bundle.records[-1]['status'],'unavailable')
        self.assertIn('Forbidden',self.bundle.records[-1]['error'])

    @patch('troubleshoot.shutil.which',return_value='oc')
    @patch('troubleshoot.subprocess.run')
    def test_absent_optional_vmi_is_distinct(self,run,which):
        run.return_value=SimpleNamespace(returncode=0,stdout='',stderr='')
        self.assertIsNone(t.OC('context',self.bundle).get(t.VMI,'vm',optional=True))
        self.assertTrue(self.bundle.records[-1]['absent'])

    @patch('troubleshoot.shutil.which',return_value='oc')
    def test_deadline_prevents_request(self,which):
        with patch('troubleshoot.subprocess.run') as run:
            with self.assertRaises(RuntimeError):t.OC('context',self.bundle,deadline=0.001).run(['get','pods'])
            run.assert_not_called()


class CollectionTests(TestCase):
    @patch('troubleshoot.shutil.which',return_value='oc')
    def test_end_to_end_graph_logs_previous_containers_and_report(self,which):
        def metadata(name,uid,namespace='apps'):
            return {'name':name,'uid':uid,'namespace':namespace}
        vm={'kind':'VirtualMachine','metadata':metadata('database','vm-uid-001'),
            'spec':{'runStrategy':'Always','template':{'spec':{'volumes':[{'name':'root','persistentVolumeClaim':{'claimName':'database-root'}},{'name':'cloudinit','cloudInitNoCloud':{'userData':'PRIVATE_CLOUDINIT_VALUE'}}]}}}}
        vmi={'kind':'VirtualMachineInstance','metadata':metadata('database','vmi-uid-001'),'spec':vm['spec']['template']['spec'],'status':{'phase':'Pending','nodeName':'worker-a'}}
        pod={'kind':'Pod','metadata':{**metadata('launcher-database','pod-uid-001'),'ownerReferences':[{'uid':'vmi-uid-001'}]},
             'spec':{'nodeName':'worker-a','containers':[{'name':'compute','env':[{'name':'PASSWORD','value':'PRIVATE_ENV_VALUE'}]}],'initContainers':[{'name':'container-disk'}]},
             'status':{'phase':'Pending','containerStatuses':[{'name':'compute','restartCount':1,'state':{'waiting':{'reason':'ContainerCreating'}}}]}}
        def controller(name,container):
            return {'kind':'Pod','metadata':metadata(name,name+'-uid','openshift-cnv'),'spec':{'nodeName':'worker-a','containers':[{'name':container,'image':'registry/'+container}]},'status':{'conditions':[{'type':'Ready','status':'True'}]}}
        shared=[controller('virt-controller-a','virt-controller'),controller('virt-handler-a','virt-handler'),controller('csi-powermax-controller','csi-attacher')]
        pvc={'kind':'PersistentVolumeClaim','metadata':metadata('database-root','pvc-uid-001'),'spec':{'volumeName':'pv-001','storageClassName':'powermax'},'status':{'phase':'Bound'}}
        pv={'kind':'PersistentVolume','metadata':metadata('pv-001','pv-uid-001',''),'spec':{'csi':{'driver':'csi-powermax.dellemc.com','volumeHandle':'real-format-handle-001'}}}
        event={'metadata':metadata('event-001','event-uid-001'),'involvedObject':{'uid':'pod-uid-001'},'reason':'FailedMount','message':'MountVolume failed for database-root','lastTimestamp':datetime.now(timezone.utc).isoformat()}
        calls=[]
        def respond(command,**options):
            calls.append(command)
            position=command.index('--request-timeout=30s')+1
            namespace=None
            if command[position]=='-n': namespace=command[position+1];position+=2
            arguments=command[position:]
            if arguments[0]=='logs':
                text='FailedAttachVolume pvc-uid-001' if 'csi-powermax-controller' in arguments else 'Failed to get write lock for disk.img' if arguments[1]=='launcher-database' else 'healthy control loop'
                return SimpleNamespace(returncode=0,stdout=text,stderr='')
            self.assertEqual(arguments[0],'get')
            resource=arguments[1]
            if resource==t.VM:value=vm
            elif resource==t.VMI:value=vmi
            elif resource=='pods':value={'items':[pod]+shared if '-A' in arguments else [pod] if namespace=='apps' else shared}
            elif resource=='persistentvolumeclaims':value=pvc
            elif resource=='persistentvolumes':value=pv
            elif resource=='storageclasses.storage.k8s.io':value={'metadata':metadata('powermax','sc-uid',''),'provisioner':'csi-powermax.dellemc.com'}
            elif resource=='nodes':value={'metadata':metadata('worker-a','node-uid-001',''),'status':{'conditions':[{'type':'Ready','status':'True'}]}}
            elif resource=='events':value={'items':[event]}
            else:value={'items':[]}
            return SimpleNamespace(returncode=0,stdout=json.dumps(value),stderr='')
        with patch('troubleshoot.subprocess.run',side_effect=respond):
            collector=t.Collector(self.args,self.bundle,t.OC(self.args.context,self.bundle)).collect()
            result=t.report(collector)
        self.assertIn('disk-image',{row['id'] for row in result['findings']})
        self.assertIn('storage-attach',{row['id'] for row in result['findings']})
        self.assertTrue(any('--previous=true' in call for call in calls))
        self.assertTrue(any('csi-attacher' in call for call in calls))
        self.assertFalse(any('secrets' in call for call in calls))
        for path in self.bundle.root.rglob('*'):
            if path.is_file():
                text=path.read_text(encoding='utf-8')
                self.assertNotIn('PRIVATE_CLOUDINIT_VALUE',text);self.assertNotIn('PRIVATE_ENV_VALUE',text)
        self.assertTrue((self.bundle.root/'summary.md').exists())

    @patch('troubleshoot.shutil.which',return_value='oc')
    def test_log_budgets_are_visible(self,which):
        collector=self.collector();collector.oc=t.OC('context',self.bundle)
        collector.args.max_log_pods=1
        def pod(name):return {'metadata':{'name':name,'namespace':'apps'},'spec':{'containers':[{'name':'compute'}]}}
        collector.pods=[(pod('one'),'workload','vm'),(pod('two'),'workload','vm')]
        with patch.object(collector,'log') as log:collector.collect_logs()
        self.assertEqual(log.call_count,1)
        self.assertTrue(any(record['category']=='log-budget' for record in self.bundle.records))


if __name__=='__main__':unittest.main()
