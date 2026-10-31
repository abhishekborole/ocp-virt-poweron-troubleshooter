"""Read-only, evidence-based OpenShift Virtualization VM power-on troubleshooting."""
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import threading
import time

VM = 'virtualmachines.kubevirt.io'
VMI = 'virtualmachineinstances.kubevirt.io'
DV = 'datavolumes.cdi.kubevirt.io'
NAD = 'network-attachment-definitions.k8s.cni.cncf.io'
TERMINAL = {'Succeeded', 'Failed'}


def now(): return datetime.now(timezone.utc).isoformat()


def duration(value):
    if not re.fullmatch(r'(?:[1-9][0-9]*[smh])+', value):
        raise argparse.ArgumentTypeError('Use a positive duration such as 30m, 2h, or 1h30m')
    return sum(int(number) * {'s': 1, 'm': 60, 'h': 3600}[unit] for number, unit in re.findall(r'([0-9]+)([smh])', value))


def redact_text(value):
    value = re.sub(r'(?i)(bearer\s+)[A-Za-z0-9._~+/=-]+', r'\1[REDACTED]', value)
    value = re.sub(r'(?i)(\b(?:password|passwd|api[_-]?token|access[_-]?token|client[_-]?secret|authorization)\b["\s]*[:=]\s*["\s]*)([^\s",;]+)', r'\1[REDACTED]', value)
    value = re.sub(r'-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----', '[REDACTED PRIVATE KEY]', value, flags=re.S)
    return value


def sanitize(value):
    """Remove common inline credential sources; do not claim universal log anonymization."""
    if isinstance(value, list): return [sanitize(item) for item in value]
    if isinstance(value, dict):
        if value.get('kind') == 'Secret': return {'kind': 'Secret', 'metadata': {'name': value.get('metadata', {}).get('name')}, 'data': '[NOT COLLECTED]'}
        result = {}
        for key, item in value.items():
            normalized = key.lower().replace('_', '').replace('-', '')
            sensitive = normalized in {'userdata', 'userdatabase64', 'networkdata', 'networkdatabase64', 'password', 'passwd', 'token', 'apitoken', 'clientsecret', 'authorization'} or key == 'kubectl.kubernetes.io/last-applied-configuration'
            if sensitive: result[key] = '[REDACTED]'
            elif key == 'env' and isinstance(item, list):
                result[key] = [{**sanitize(entry), **({'value': '[REDACTED]'} if 'value' in entry else {})} for entry in item]
            else: result[key] = sanitize(item)
        return result
    return redact_text(value) if isinstance(value, str) else value


def safe_name(value):
    # Hash avoids collisions when sanitizing slash-separated identifiers.
    readable = re.sub(r'[^A-Za-z0-9_.-]+', '_', value)[:120]
    return readable + '-' + hashlib.sha256(value.encode()).hexdigest()[:8]


def canonical(path):
    resolved = str(Path(path).resolve())
    # Windows can return the extended-length namespace for one resolved path
    # and a regular drive path for another, particularly during concurrent I/O.
    if resolved.startswith('\\\\?\\UNC\\'): resolved = '\\\\' + resolved[8:]
    elif resolved.startswith('\\\\?\\'): resolved = resolved[4:]
    return Path(resolved)


class Bundle:
    def __init__(self, root):
        self.root = canonical(root)
        self.root.mkdir(parents=True, exist_ok=False)
        self.records, self.lock = [], threading.Lock()

    def write(self, artifact_name, content, category, scope='context', **metadata):
        relative = Path(artifact_name)
        target = canonical(self.root / relative)
        if not target.is_relative_to(self.root): raise ValueError(f'Artifact path escapes the report directory: {target} outside {self.root}')
        target.parent.mkdir(parents=True, exist_ok=True)
        rendered = json.dumps(sanitize(content), indent=2, ensure_ascii=False) if not isinstance(content, str) else redact_text(content)
        target.write_text(rendered + '\n', encoding='utf-8')
        record = {'artifact': relative.as_posix(), 'category': category, 'scope': scope, 'status': 'collected', **metadata}
        with self.lock: self.records.append(record)
        return record

    def gap(self, category, message, **metadata):
        record = {'category': category, 'status': 'unavailable', 'error': redact_text(message), **metadata}
        with self.lock: self.records.append(record)


class OC:
    def __init__(self, context, bundle, timeout=40, deadline=None):
        self.executable = shutil.which('oc')
        if not self.executable: raise RuntimeError('oc was not found. Install a supported oc client and authenticate with oc login.')
        self.context, self.bundle, self.timeout = context, bundle, timeout
        self.deadline = deadline

    def run(self, arguments, namespace=None, category='api'):
        remaining = self.deadline - time.monotonic() if self.deadline else self.timeout
        if remaining <= 0: raise RuntimeError('Collection deadline reached')
        command = [self.executable, '--context', self.context, '--request-timeout=30s']
        if namespace: command += ['-n', namespace]
        command += list(arguments)
        # No shell, credential arguments, exec, apply, patch, delete, or privileged pods.
        result = subprocess.run(command, capture_output=True, text=True, encoding='utf-8', errors='replace',
                                timeout=min(self.timeout, remaining), shell=False)
        if result.returncode: raise RuntimeError(result.stderr.strip() or result.stdout.strip() or 'oc failed')
        return result.stdout

    def get(self, resource, name=None, namespace=None, optional=False, all_namespaces=False, category=None, scope='context'):
        category = category or resource
        args = ['get', resource]
        if name: args.append(name)
        if optional: args.append('--ignore-not-found')
        if all_namespaces: args.append('-A')
        args += ['-o', 'json']
        try:
            raw = self.run(args, namespace)
            if not raw.strip():
                self.bundle.gap(category, 'Object is currently absent', resource=resource, name=name, namespace=namespace, absent=True)
                return None
            value = json.loads(raw)
            identity = '/'.join([namespace or 'cluster', resource, name or 'list'])
            self.bundle.write('objects/' + safe_name(identity) + '.json', value, category, scope, namespace=namespace, name=name, resource=resource)
            return value
        except (RuntimeError, OSError, subprocess.SubprocessError, ValueError) as error:
            self.bundle.gap(category, str(error), resource=resource, name=name, namespace=namespace)
            return None


def items(value): return value.get('items', []) if value else []


def owner_uids(obj): return {reference.get('uid') for reference in obj.get('metadata', {}).get('ownerReferences', [])}


def pod_statuses(pod):
    status = pod.get('status', {})
    return status.get('initContainerStatuses', []) + status.get('containerStatuses', []) + status.get('ephemeralContainerStatuses', [])


def related_pod(pod, uids, claims):
    if owner_uids(pod) & uids: return True
    labels = pod.get('metadata', {}).get('labels', {})
    if labels.get('kubevirt.io/created-by') in uids: return True
    return any(volume.get('persistentVolumeClaim', {}).get('claimName') in claims for volume in pod.get('spec', {}).get('volumes', []))


def component(pod, drivers, csi_namespaces):
    metadata, spec = pod.get('metadata', {}), pod.get('spec', {})
    text = json.dumps({'name': metadata.get('name'), 'labels': metadata.get('labels', {}),
                       'containers': [{'name': c.get('name'), 'image': c.get('image'), 'args': c.get('args'), 'command': c.get('command')} for c in spec.get('containers', [])]}).lower()
    for name in ('virt-controller', 'virt-handler', 'virt-api', 'virt-operator', 'cdi-deployment', 'cdi-apiserver', 'cdi-operator', 'hco-operator'):
        if name in text: return name
    if metadata.get('namespace') in csi_namespaces: return 'csi-explicit-namespace'
    prefixes = [driver.split('.')[0].lower() for driver in drivers if len(driver.split('.')[0]) >= 4]
    if any(prefix in text for prefix in prefixes): return 'csi-driver-match'
    if any(marker in text for marker in ('csi-provisioner', 'csi-attacher', 'csi-resizer', 'csi-snapshotter', 'node-driver-registrar', 'csi-node-driver', 'csi-node', 'csi-controller')):
        return 'csi-discovered'
    return None


def event_time(event):
    value = event.get('series', {}).get('lastObservedTime') or event.get('lastTimestamp') or event.get('eventTime') or event.get('metadata', {}).get('creationTimestamp')
    try: return datetime.fromisoformat(value.replace('Z', '+00:00')) if value else None
    except ValueError: return None


def filter_events(events, uids, references, cutoff):
    result = []
    for event in events:
        involved = event.get('involvedObject', event.get('regarding', {}))
        # A matching name with a different UID belongs to a prior/recreated object.
        matched = involved.get('uid') in uids if involved.get('uid') else (involved.get('namespace', ''), involved.get('kind'), involved.get('name')) in references
        timestamp = event_time(event)
        if matched and (timestamp is None or timestamp >= cutoff): result.append(event)
    return result


class Collector:
    def __init__(self, args, bundle, oc):
        self.args, self.bundle, self.oc = args, bundle, oc
        self.vm, self.vmi = None, None
        self.pvcs, self.pvs, self.dvs, self.nodes, self.attachments = [], [], [], [], []
        self.pods, self.events, self.identifiers = [], [], set()

    def object(self, resource, name=None, namespace=None, **kwargs): return self.oc.get(resource, name, namespace, **kwargs)

    def collect(self):
        args, ns = self.args, self.args.namespace
        self.vm = self.object(VM, args.vm, ns, category='vm', scope='vm')
        if not self.vm: raise RuntimeError('Cannot read the selected VM. See collection.json for the API error; check context, namespace, name, and RBAC.')
        self.vmi = self.object(VMI, args.vm, ns, optional=True, category='vmi', scope='vm')
        uids = {self.vm['metadata']['uid']}
        if self.vmi: uids.add(self.vmi['metadata']['uid'])
        self.identifiers |= uids
        claims, dv_names = set(), set()
        specs = [self.vm.get('spec', {}).get('template', {}).get('spec', {})]
        if self.vmi: specs.append(self.vmi.get('spec', {}))
        for spec in specs:
            for volume in spec.get('volumes', []):
                claim = volume.get('persistentVolumeClaim', {}).get('claimName')
                if claim: claims.add(claim)
                name = volume.get('dataVolume', {}).get('name')
                if name: dv_names.add(name); claims.add(name)
            for network in spec.get('networks', []):
                reference = network.get('multus', {}).get('networkName')
                if reference:
                    network_ns, name = reference.split('/', 1) if '/' in reference else (ns, reference)
                    self.object(NAD, name, network_ns, optional=True, category='network-attachment', scope='vm')
        dv_names |= {template['metadata']['name'] for template in self.vm.get('spec', {}).get('dataVolumeTemplates', [])}
        for name in sorted(dv_names):
            dv = self.object(DV, name, ns, optional=True, category='datavolume', scope='vm')
            if dv:
                self.dvs.append(dv); uids.add(dv['metadata']['uid'])
                claims.add(dv.get('status', {}).get('claimName') or name)
        drivers, storage_classes = set(), set()
        for name in sorted(claims):
            pvc = self.object('persistentvolumeclaims', name, ns, optional=True, category='pvc', scope='vm')
            if not pvc: continue
            self.pvcs.append(pvc); uids.add(pvc['metadata']['uid'])
            if pvc['spec'].get('storageClassName'): storage_classes.add(pvc['spec']['storageClassName'])
            if pvc['spec'].get('volumeName'):
                pv = self.object('persistentvolumes', pvc['spec']['volumeName'], category='pv', scope='vm')
                if pv:
                    self.pvs.append(pv); uids.add(pv['metadata']['uid'])
                    csi = pv.get('spec', {}).get('csi', {})
                    if csi.get('driver'): drivers.add(csi['driver'])
                    if csi.get('volumeHandle'): self.identifiers.add(csi['volumeHandle'])
        for name in sorted(storage_classes):
            storage_class = self.object('storageclasses.storage.k8s.io', name, category='storageclass')
            if storage_class and storage_class.get('provisioner'): drivers.add(storage_class['provisioner'])
        for driver in sorted(drivers): self.object('csidrivers.storage.k8s.io', driver, optional=True, category='csidriver')
        attachments = items(self.object('volumeattachments.storage.k8s.io', category='volumeattachment-discovery'))
        pv_names = {pv['metadata']['name'] for pv in self.pvs}
        self.attachments = [a for a in attachments if a.get('spec', {}).get('source', {}).get('persistentVolumeName') in pv_names]
        # Save only the VM's attachment data in a focused artifact as well.
        self.bundle.write('objects/related-volumeattachments.json', self.attachments, 'related-volumeattachments', 'vm')
        for attachment in self.attachments: uids.add(attachment['metadata']['uid'])
        local_pods = items(self.object('pods', namespace=ns, category='workload-pod-discovery'))
        relevant = [p for p in local_pods if related_pod(p, uids, claims)]
        nodes = {p.get('spec', {}).get('nodeName') for p in relevant}
        if self.vmi: nodes.add(self.vmi.get('status', {}).get('nodeName'))
        nodes |= {pvc.get('metadata', {}).get('annotations', {}).get('volume.kubernetes.io/selected-node') for pvc in self.pvcs}
        nodes.discard(None); nodes.discard('')
        for name in sorted(nodes):
            node = self.object('nodes', name, category='node', scope='vm')
            if node: self.nodes.append(node); uids.add(node['metadata']['uid'])
            self.object('csinodes.storage.k8s.io', name, optional=True, category='csinode', scope='vm')
        for resource in ('resourcequotas', 'limitranges'):
            self.object(resource, namespace=ns, category=resource, scope='vm')
        for reference_key, resources in (('instancetype', {'virtualmachineinstancetype': 'virtualmachineinstancetypes.instancetype.kubevirt.io', 'virtualmachineclusterinstancetype': 'virtualmachineclusterinstancetypes.instancetype.kubevirt.io'}),
                                         ('preference', {'virtualmachinepreference': 'virtualmachinepreferences.instancetype.kubevirt.io', 'virtualmachineclusterpreference': 'virtualmachineclusterpreferences.instancetype.kubevirt.io'})):
            reference = self.vm.get('spec', {}).get(reference_key, {})
            if reference.get('name'):
                default = 'virtualmachinecluster' + reference_key
                kind = reference.get('kind', default).lower()
                if kind in resources:
                    self.object(resources[kind], reference['name'], ns if 'cluster' not in kind else None, optional=True, category=reference_key, scope='vm')
        all_pods_result = self.object('pods', all_namespaces=True, category='component-discovery')
        all_pods = items(all_pods_result)
        if all_pods_result is None:
            # Best effort when cluster-wide pod listing is denied.
            fallback = {args.virt_namespace, 'openshift-cluster-csi-drivers', 'openshift-storage', *args.csi_namespace}
            for namespace in sorted(fallback): all_pods += items(self.object('pods', namespace=namespace, category='component-fallback-discovery'))
        selected = {(p['metadata']['namespace'], p['metadata']['name']): (p, 'workload', 'vm') for p in relevant}
        for pod in all_pods:
            kind = component(pod, drivers, set(args.csi_namespace))
            if not kind: continue
            # Node plugins and handlers on other nodes cannot explain this node's start failure.
            containers = pod.get('spec', {}).get('containers', [])
            node_plugin = any('node-driver-registrar' in json.dumps(c).lower() for c in containers)
            if nodes and (kind == 'virt-handler' or node_plugin) and pod.get('spec', {}).get('nodeName') not in nodes: continue
            key = (pod['metadata']['namespace'], pod['metadata']['name'])
            selected.setdefault(key, (pod, kind, 'shared'))
        self.pods = list(selected.values())
        discovered = {kind for _, kind, _ in self.pods}
        for expected in ('virt-controller', 'virt-handler'):
            if expected not in discovered:
                self.bundle.gap('component-discovery', 'No matching pods were discovered; component logs were not collected', component=expected)
        if drivers and not any(kind.startswith('csi-') for kind in discovered):
            self.bundle.gap('component-discovery', 'No CSI pods were discovered for the referenced storage; supply --csi-namespace for custom deployments', drivers=sorted(drivers))
        for pod, kind, scope in self.pods:
            if scope == 'vm': uids.add(pod['metadata']['uid'])
        self.identifiers |= uids | {claim for claim in claims if len(claim) >= 5}
        self.identifiers.add(ns + '/' + args.vm)
        references = {(ns, 'VirtualMachine', args.vm), (ns, 'VirtualMachineInstance', args.vm)}
        references |= {(p['metadata']['namespace'], 'Pod', p['metadata']['name']) for p, kind, scope in self.pods if scope == 'vm'}
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=duration(args.since))
        namespaces = {ns, *[p['metadata']['namespace'] for p, _, _ in self.pods]}
        for namespace in sorted(namespaces):
            events = items(self.object('events', namespace=namespace, category='event-discovery'))
            self.events += filter_events(events, uids, references, cutoff)
        self.events += filter_events(items(self.object('events', namespace=None, all_namespaces=True, category='cluster-event-discovery')), uids, references, cutoff)
        unique = {event.get('metadata', {}).get('uid', json.dumps(event, sort_keys=True)): event for event in self.events}
        self.events = list(unique.values())
        self.bundle.write('objects/related-events.json', self.events, 'related-events', 'vm')
        self.object('hyperconvergeds.hco.kubevirt.io', namespace=args.virt_namespace, category='hco')
        self.object('kubevirts.kubevirt.io', namespace=args.virt_namespace, category='kubevirt')
        self.object('clusteroperators.config.openshift.io', 'storage', category='storage-operator')
        self.collect_logs()
        if args.node_journal:
            for node in sorted(nodes):
                try:
                    since_timestamp = (datetime.now(timezone.utc)-timedelta(seconds=duration(args.since))).strftime('%Y-%m-%dT%H:%M:%SZ')
                    log = self.oc.run(['adm', 'node-logs', node, '-u', 'kubelet', '--since', since_timestamp, '--tail', str(args.tail_lines)])
                    self.bundle.write('logs/' + safe_name(node) + '-kubelet.log', log, 'kubelet', 'shared', node=node)
                except (RuntimeError, OSError, subprocess.SubprocessError) as error: self.bundle.gap('kubelet', str(error), node=node)
        return self

    def collect_logs(self):
        selected = sorted(self.pods, key=lambda row: (row[2] != 'vm', not row[1].startswith('virt-'), row[0]['metadata']['namespace'], row[0]['metadata']['name']))
        for pod, kind, scope in selected:
            identity = pod['metadata']['namespace'] + '/' + pod['metadata']['name']
            self.bundle.write('pods/' + safe_name(identity) + '.json', pod, 'selected-pod', scope, component=kind, namespace=pod['metadata']['namespace'], pod=pod['metadata']['name'])
        if len(selected) > self.args.max_log_pods:
            self.bundle.gap('log-budget', 'Pod limit reached; increase --max-log-pods to collect the omitted component pods', omitted_pods=[p['metadata']['namespace']+'/'+p['metadata']['name'] for p, _, _ in selected[self.args.max_log_pods:]])
        jobs = []
        for pod, kind, scope in selected[:self.args.max_log_pods]:
            statuses = {s['name']: s for s in pod_statuses(pod)}
            spec = pod.get('spec', {})
            for container in spec.get('initContainers', []) + spec.get('containers', []) + spec.get('ephemeralContainers', []):
                name = container['name']
                jobs.append((pod, kind, scope, name, False))
                if statuses.get(name, {}).get('restartCount', 0) > 0: jobs.append((pod, kind, scope, name, True))
        if len(jobs) > self.args.max_log_requests:
            self.bundle.gap('log-budget', 'Container request limit reached', omitted_requests=len(jobs)-self.args.max_log_requests)
        with ThreadPoolExecutor(max_workers=self.args.workers) as pool:
            futures = [pool.submit(self.log, *job) for job in jobs[:self.args.max_log_requests]]
            for future in as_completed(futures): future.result()

    def log(self, pod, kind, scope, container, previous):
        namespace, name = pod['metadata']['namespace'], pod['metadata']['name']
        arguments = ['logs', name, '-c', container, '--since=' + self.args.since, '--tail=' + str(self.args.tail_lines), '--limit-bytes=' + str(self.args.limit_bytes), '--timestamps=true']
        if previous: arguments.append('--previous=true')
        identity = '/'.join([namespace, name, container, 'previous' if previous else 'current'])
        try:
            text = self.oc.run(arguments, namespace)
            self.bundle.write('logs/' + safe_name(identity) + '.log', text, 'container-log', scope,
                              component=kind, namespace=namespace, pod=name, container=container, previous=previous,
                              empty=not text.strip(), byte_limit=self.args.limit_bytes, tail_limit=self.args.tail_lines)
        except (RuntimeError, OSError, subprocess.SubprocessError) as error:
            self.bundle.gap('container-log', str(error), component=kind, namespace=namespace, pod=name, container=container, previous=previous)


# Rules produce hypotheses with review steps, not automatic remediation.
RULES = [
    ('storage-attach', 'Storage attachment or multi-attach conflict', r'Multi-Attach|FailedAttachVolume|AttachVolume.Attach failed|VolumeAttachment.*(?:error|fail)|volume.*already (?:attached|in use)', 'Inspect the named VolumeAttachment, CSI attacher/controller and node-plugin logs, array host mapping, and whether another node still owns the disk. Do not force-detach a disk without establishing the old owner is fenced.'),
    ('storage-mount', 'Storage mount, stage, or publish failure', r'FailedMount|MountVolume.*failed|NodeStageVolume.*(?:error|fail)|NodePublishVolume.*(?:error|fail)|mount.*(?:permission denied|timed out|not found)', 'Compare PVC/PV, CSI node registration, target-node plugin logs, filesystem/mount details, and array connectivity. Use the exact CSI error and volume handle to select the next check.'),
    ('storage-provisioning', 'Volume provisioning is failing', r'ProvisioningFailed|failed to provision volume|no persistent volumes available|storageclass.*not found', 'Inspect PVC events, StorageClass provisioner/parameters, CSI provisioner logs, backend pool capacity, and storage permissions.'),
    ('capacity', 'Insufficient schedulable CPU, memory, or virtualization resources', r'Insufficient (?:cpu|memory|hugepages|devices.kubevirt.io/\w+)|out of (?:memory|cpu)|not enough (?:memory|cpu)', 'Review the exact scheduler message, requests/limits, hugepages, KVM/device resources, and eligible node capacity. Do not resize or move workloads solely from this heuristic.'),
    ('placement', 'Node selectors, affinity, taints, or volume topology block scheduling', r"didn.t match.*(?:affinity|selector)|untolerated taint|volume node affinity conflict|node\(s\).*unschedulable|FailedScheduling", 'Inspect PodScheduled conditions, nodeSelector/affinity, tolerations, selected-node annotations, PV nodeAffinity and storage topology. FailedScheduling is a symptom; the message identifies the constraint.'),
    ('image-pull', 'A container or container-disk image cannot be pulled', r'ErrImagePull|ImagePullBackOff|FailedToRetrieveImagePullSecret|pull access denied|manifest unknown|unauthorized.*(?:registry|image)', 'Verify the exact image reference, registry availability and trust, proxy/network access, and referenced image-pull Secret. Do not include Secret values in a support bundle.'),
    ('admission', 'Admission, quota, or security policy rejected workload creation', r'exceeded quota|FailedCreate.*(?:forbidden|denied)|unable to validate against any security context constraint|violates PodSecurity|admission webhook.*denied|is forbidden.*(?:quota|serviceaccount)', 'Inspect VM/controller events, ResourceQuota/LimitRange, service account and SCC/admission policy. Correct the specific rejected field or permission rather than granting broad privileges.'),
    ('network', 'CNI or Multus network setup failed', r'FailedCreatePodSandBox|Multus.*(?:error|fail)|network-attachment-definition.*not found|failed to (?:create|setup).*network|failed to allocate.*(?:IP|address)', 'Inspect the launcher pod event, named NAD, node CNI/Multus logs, VLAN/bridge mappings, and IPAM. Validate the exact attachment before changing guest networking.'),
    ('disk-image', 'Disk image or QEMU disk access prevents startup', r'Failed to get.*write.*lock|Could not open.*(?:disk|qcow|img)|invalid.*(?:qcow|disk image)|No space left on device|read-only file system', 'Inspect compute-container logs, the referenced disk path and PVC, image format, storage free space and disk ownership. A write-lock error can indicate another live owner; do not remove locks blindly.'),
    ('domain', 'QEMU/libvirt or virtualization-device startup failed', r'failed to (?:define|start).*domain|QEMU unexpectedly closed|failed to initialize kvm|/dev/kvm.*(?:denied|not found)|CPU.*(?:incompatible|not supported)|unsupported CPU', 'Inspect virt-handler and compute logs on the selected node, CPU model/feature compatibility, KVM device access, and domain error details.'),
    ('import', 'DataVolume import or clone is failing', r'ImportFailed|CloneFailed|DataVolume.*(?:Failed|Error)|error.*(?:importing|cloning)|ImagePullFailed', 'Inspect the DataVolume conditions, importer/clone pod logs, source URL or registry access, source TLS trust, scratch space, and destination PVC events.'),
    ('container-config', 'Container configuration or referenced object is missing', r'CreateContainerConfigError|secret ["\x27]?.+ not found|configmap ["\x27]?.+ not found', 'Inspect waiting-container messages and referenced object names in the selected namespace. Confirm existence and RBAC without exporting Secret data.'),
    ('oom', 'A relevant container was killed for memory pressure', r'\bOOMKilled\b|out of memory: killed process', 'Inspect the terminated container, memory requests/limits and node pressure. Distinguish launcher/QEMU memory overhead from guest memory before changing sizing.'),
]


def correlated(line, identifiers, namespace, vm):
    for identifier in identifiers:
        if len(identifier) >= 5 and re.search(r'(?<![\w-])' + re.escape(identifier) + r'(?![\w-])', line, re.I): return True
    return bool(re.search(r'(?<![\w-])' + re.escape(vm) + r'(?![\w-])', line) and re.search(r'(?<![\w-])' + re.escape(namespace) + r'(?![\w-])', line))


def diagnose(collector):
    bundle, args = collector.bundle, collector.args
    findings = {}

    def add(key, title, confidence, evidence, action):
        finding = findings.setdefault(key, {'id': key, 'possibility': title, 'confidence': confidence, 'evidence': [], 'next_check': action})
        if {'high': 3, 'medium': 2, 'low': 1}[confidence] > {'high': 3, 'medium': 2, 'low': 1}[finding['confidence']]: finding['confidence'] = confidence
        if len(finding['evidence']) < 12 and evidence not in finding['evidence']: finding['evidence'].append(evidence)

    def artifact_for(resource, name):
        return next((record['artifact'] for record in bundle.records if record.get('resource') == resource and record.get('name') == name and record.get('artifact')), None)

    vm = collector.vm or {}
    vm_spec = vm.get('spec', {})
    if vm_spec.get('runStrategy') == 'Halted' or vm_spec.get('running') is False:
        add('not-requested', 'VM configuration does not request automatic power-on', 'high',
            {'artifact': artifact_for(VM, args.vm), 'field': 'spec.runStrategy/spec.running', 'detail': f"runStrategy={vm_spec.get('runStrategy')}, running={vm_spec.get('running')}"},
            'Confirm whether the VM was intentionally stopped or a manual start was requested. Use the supported virtctl start workflow only after confirming the intended state.')
    for record in bundle.records:
        if record.get('absent') and record.get('category') in ('pvc','datavolume','network-attachment','instancetype','preference'):
            add('missing-reference', 'A referenced storage/network/VM configuration object is currently absent', 'medium',
                {'artifact': None, 'field': record.get('resource'), 'detail': str(record.get('namespace'))+'/'+str(record.get('name'))+': '+record['error']},
                'Verify the exact reference and namespace. PVC/DataVolume creation can still be pending reconciliation; inspect VM/controller events and conditions before deciding whether the reference itself is wrong.')
    for pvc in collector.pvcs:
        if pvc.get('status', {}).get('phase') != 'Bound':
            add('pvc-pending', 'A referenced PVC is not Bound; provisioning or first-consumer scheduling needs review', 'medium',
                {'artifact': artifact_for('persistentvolumeclaims', pvc['metadata']['name']), 'field': 'status.phase', 'detail': str(pvc.get('status', {}).get('phase'))},
                'Check StorageClass volumeBindingMode and related PVC/pod events. WaitForFirstConsumer can be expected until scheduling succeeds; do not treat it alone as a backend failure.')
    for dv in collector.dvs:
        phase = dv.get('status', {}).get('phase')
        if phase not in ('Succeeded',):
            add('dv-not-ready', 'A referenced DataVolume is not yet ready', 'medium', {'artifact': artifact_for(DV, dv['metadata']['name']), 'field': 'status.phase', 'detail': str(phase)},
                'Inspect DataVolume conditions and importer/clone logs. Active import is not necessarily a failure; distinguish progress from repeated errors.')
    for node in collector.nodes:
        for condition in node.get('status', {}).get('conditions', []):
            failed = condition.get('type') == 'Ready' and condition.get('status') != 'True'
            pressure = condition.get('type') in ('MemoryPressure', 'DiskPressure', 'PIDPressure') and condition.get('status') == 'True'
            if failed or pressure:
                add('node-health', 'The VM-associated node reports unhealthy conditions', 'high', {'artifact': artifact_for('nodes', node['metadata']['name']), 'field': 'status.conditions', 'detail': json.dumps(condition)},
                    'Investigate node readiness/pressure, kubelet and virt-handler health before retrying the VM. Node recovery can require administrator or vendor intervention.')
    for pod, kind, scope in collector.pods:
        if scope != 'vm': continue
        for status in pod_statuses(pod):
            state = status.get('state', {})
            terminated = state.get('terminated') or status.get('lastState', {}).get('terminated', {})
            waiting = state.get('waiting', {})
            details = json.dumps({'container': status['name'], 'waiting': waiting, 'terminated': terminated})
            for key, title, pattern, action in RULES:
                if re.search(pattern, details, re.I):
                    add(key, title, 'high', {'artifact': next((r['artifact'] for r in bundle.records if r.get('category') == 'selected-pod' and r.get('pod') == pod['metadata']['name'] and r.get('namespace') == pod['metadata']['namespace']), None), 'field': 'status.containerStatuses', 'detail': redact_text(details)}, action)
    groups = {}
    for pod, kind, scope in collector.pods:
        if scope == 'shared': groups.setdefault(kind, []).append(pod)
    for kind, pods in groups.items():
        ready = [pod for pod in pods if any(c.get('type') == 'Ready' and c.get('status') == 'True' for c in pod.get('status', {}).get('conditions', []))]
        if not ready:
            names = [pod['metadata']['namespace']+'/'+pod['metadata']['name'] for pod in pods]
            add('component-'+kind, 'Discovered '+kind+' pods are not Ready', 'medium',
                {'artifact': next((r['artifact'] for r in bundle.records if r.get('category') == 'selected-pod' and r.get('component') == kind), None), 'detail': ', '.join(names)},
                'Inspect container states, current/previous logs, operator conditions and deployment/daemonset health. This is a component-health observation; confirm whether it explains this VM failure.')
    # Search focused VM events and conditions only. Whole pod specs/annotations are not error evidence.
    focused = []
    for event in collector.events:
        focused.append(('objects/related-events.json', event.get('reason', '') + ': ' + event.get('message', event.get('note', '')), 'high'))
    for obj, resource in ((collector.vm, VM), (collector.vmi, VMI)):
        if not obj: continue
        for condition in obj.get('status', {}).get('conditions', []):
            focused.append((artifact_for(resource, args.vm), json.dumps(condition), 'high'))
    for pod, kind, scope in collector.pods:
        if scope == 'vm':
            artifact = next((r['artifact'] for r in bundle.records if r.get('category') == 'selected-pod' and r.get('pod') == pod['metadata']['name'] and r.get('namespace') == pod['metadata']['namespace']), None)
            for condition in pod.get('status', {}).get('conditions', []): focused.append((artifact, json.dumps(condition), 'high'))
    for obj, resource in [(pvc,'persistentvolumeclaims') for pvc in collector.pvcs] + [(dv,DV) for dv in collector.dvs]:
        for condition in obj.get('status', {}).get('conditions', []):
            focused.append((artifact_for(resource,obj['metadata']['name']),json.dumps(condition),'high'))
    for attachment in collector.attachments:
        for field in ('attachError', 'detachError'):
            error = attachment.get('status', {}).get(field)
            if error:
                add('storage-attach', 'CSI volume attachment/detachment reports an error', 'high', {'artifact': 'objects/related-volumeattachments.json', 'field': 'status.' + field, 'detail': json.dumps(error)}, RULES[0][3])
    for artifact, text, confidence in focused:
        for key, title, pattern, action in RULES:
            if re.search(pattern, text, re.I): add(key, title, confidence, {'artifact': artifact, 'detail': redact_text(text)[:2000]}, action)
    uncorrelated = 0
    for record in bundle.records:
        if record.get('category') not in ('container-log', 'kubelet') or record.get('status') != 'collected': continue
        text = (bundle.root / record['artifact']).read_text(encoding='utf-8')
        for line_number, line in enumerate(text.splitlines(), 1):
            matches = [(key, title, action) for key, title, pattern, action in RULES if re.search(pattern, line, re.I)]
            if not matches: continue
            if record['scope'] != 'vm' and not correlated(line, collector.identifiers, args.namespace, args.vm):
                uncorrelated += 1; continue
            for key, title, action in matches:
                add(key, title, 'high' if record['scope'] == 'vm' else 'medium',
                    {'artifact': record['artifact'], 'line': line_number, 'detail': line[:2000], 'correlation': 'VM workload container' if record['scope'] == 'vm' else 'VM/PVC/volume identifier in shared log line'}, action)
    return sorted(findings.values(), key=lambda finding: (-{'high': 3, 'medium': 2, 'low': 1}[finding['confidence']], finding['id'])), uncorrelated


def report(collector, fatal=None):
    bundle, args = collector.bundle, collector.args
    findings, unrelated = diagnose(collector)
    gaps = [record for record in bundle.records if record['status'] == 'unavailable']
    logs = [record for record in bundle.records if record['category'] == 'container-log' and record['status'] == 'collected']
    result = {'created_at': now(), 'context': args.context, 'namespace': args.namespace, 'vm': args.vm,
              'fatal': fatal, 'vmi_phase': (collector.vmi or {}).get('status', {}).get('phase'),
              'findings': findings, 'unrelated_shared_error_lines_not_promoted': unrelated,
              'coverage': {'selected_pods': len(collector.pods), 'collected_container_logs': len(logs), 'unavailable_items': len(gaps),
                           'since': args.since, 'tail_lines_per_container': args.tail_lines, 'bytes_per_container': args.limit_bytes},
              'limitations': ['Possibilities are evidence-based hypotheses, not confirmed root causes.',
                              'Only retained logs in the selected time/line/byte budgets are available. Earlier container incarnations may be gone.',
                              'CSI discovery uses pod metadata/container markers and driver-name matches; explicitly supply custom CSI namespaces.',
                              'API authorization failures and absent resources are recorded separately from healthy observations.',
                              'Guest OS console, array-side logs, CNI node filesystem logs, and inaccessible/deleted pod logs are not automatically available.',
                              'Redaction is best effort; review this locally collected bundle before sharing.'],
              'unavailable': gaps}
    lines = [f'# VM power-on troubleshooting: {args.namespace}/{args.vm}', '', f'Context: `{args.context}` · Collected: {result["created_at"]}', '',
             f'VMI phase: **{result["vmi_phase"] or "not observed"}**. Container logs collected: **{len(logs)}**. Unavailable/absent items: **{len(gaps)}**.', '',
             'Findings are possibilities ranked by evidence strength, not proof of root cause. Shared log errors without a VM/PVC/volume correlation are excluded.', '']
    if fatal: lines += ['## Collection error', '', fatal, '']
    if result['vmi_phase'] == 'Running': lines += ['The VMI is currently Running. This confirms a running VMI, not a healthy guest OS; findings may describe a recent/transient startup failure.', '']
    lines += ['## Possibilities', '']
    if not findings: lines += ['No supported failure signature was found in the evidence collected. This is inconclusive, especially when logs or API objects were unavailable.', '']
    for finding in findings:
        lines += [f'### {finding["possibility"]} ({finding["confidence"]} evidence confidence)', '', finding['next_check'], '']
        for evidence in finding['evidence']:
            location = evidence.get('artifact') or 'object observation'
            if evidence.get('line'): location += ':' + str(evidence['line'])
            lines += [f'- `{location}`: {evidence["detail"].replace(chr(10), " ")[:1500]}']
        lines.append('')
    lines += ['## Collection coverage and unavailable evidence', '', f'Ignored **{unrelated}** matching shared-log lines without VM correlation.', '',
              'See [collection.json](collection.json) for every successful artifact and failed/absent request. Log retention and configured budgets apply even when no request failed.', '']
    for gap in gaps: lines += [f'- **{gap["category"]}** {gap.get("namespace") or ""}/{gap.get("pod") or gap.get("name") or ""}: {gap["error"]}']
    lines += ['', '## Limits', '', *['- ' + limitation for limitation in result['limitations']], '']
    bundle.write('summary.json', result, 'summary')
    bundle.write('summary.md', '\n'.join(lines), 'summary')
    # Collection manifest deliberately includes the summaries and all retrieval gaps.
    (bundle.root / 'collection.json').write_text(json.dumps(sanitize(bundle.records), indent=2) + '\n', encoding='utf-8')
    return result


def parser():
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument('--context', required=True, help='Existing authenticated oc kubeconfig context')
    result.add_argument('--namespace', required=True)
    result.add_argument('--vm', required=True)
    result.add_argument('--output', type=Path, help='New report directory; existing paths are never overwritten')
    result.add_argument('--since', default='1h', help='Log/event lookback such as 30m, 1h, or 1h30m')
    result.add_argument('--tail-lines', type=int, default=2000)
    result.add_argument('--limit-bytes', type=int, default=1024*1024)
    result.add_argument('--max-log-pods', type=int, default=80)
    result.add_argument('--max-log-requests', type=int, default=300)
    result.add_argument('--workers', type=int, default=6)
    result.add_argument('--collection-timeout', type=int, default=600, help='Overall request deadline in seconds')
    result.add_argument('--virt-namespace', default='openshift-cnv')
    result.add_argument('--csi-namespace', action='append', default=[], help='Also include pods in this CSI namespace; repeat for custom drivers')
    result.add_argument('--node-journal', action='store_true', help='Also request kubelet journal via oc adm node-logs; requires elevated read privileges')
    return result


def main(argv=None):
    command = parser(); args = command.parse_args(argv)
    try: duration(args.since)
    except argparse.ArgumentTypeError as error: command.error(str(error))
    if not 1 <= args.workers <= 16: command.error('--workers must be between 1 and 16')
    if args.tail_lines > 100000: command.error('--tail-lines cannot exceed 100000')
    for name in ('tail_lines', 'limit_bytes', 'max_log_pods', 'max_log_requests', 'collection_timeout'):
        if getattr(args, name) <= 0: command.error('--' + name.replace('_', '-') + ' must be positive')
    if any(value.startswith('-') for value in (args.context, args.namespace, args.vm, args.virt_namespace, *args.csi_namespace)):
        command.error('Identifiers cannot start with a dash')
    output = args.output or Path('reports') / (safe_name(args.namespace + '-' + args.vm) + '-' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'))
    try:
        bundle = Bundle(output)
        oc = OC(args.context, bundle, deadline=time.monotonic() + args.collection_timeout)
    except (OSError, RuntimeError) as error:
        print(str(error), file=sys.stderr); return 2
    collector = Collector(args, bundle, oc)
    fatal = None
    try: collector.collect()
    except (RuntimeError, OSError, ValueError, KeyError, subprocess.SubprocessError) as error: fatal = str(error)
    result = report(collector, fatal)
    print(json.dumps({'report': str(bundle.root / 'summary.md'), 'findings': len(result['findings']), 'unavailable_items': result['coverage']['unavailable_items'], 'fatal': fatal}, indent=2))
    # 0: complete best-effort collection; 1: partial evidence; 2: fatal target/collection failure.
    if fatal: return 2
    gaps = [gap for gap in result['unavailable'] if not gap.get('absent')]
    return 1 if gaps else 0


if __name__ == '__main__': raise SystemExit(main())
