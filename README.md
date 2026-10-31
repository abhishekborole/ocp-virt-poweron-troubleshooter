# OpenShift Virtualization VM power-on troubleshooter

Collect live evidence for **one VM that will not power on**, follow its storage and pod dependencies, and produce a ranked list of possible causes with evidence files and next checks. Targets OpenShift **4.20+** with OpenShift Virtualization.

This is a read-only Python tool using your authenticated `oc` session. It does not start/stop VMs, restart controllers, change RBAC, force-detach disks, or deploy diagnostic pods.

## Run against your infrastructure

Requires Python 3.11+, a vendor-supported `oc` client, an authenticated kubeconfig context, and read access to the relevant resources/logs. No third-party Python dependencies.

```powershell
oc login https://YOUR_API_ENDPOINT
oc config get-contexts

python troubleshoot.py --context YOUR_CONTEXT --namespace YOUR_NAMESPACE --vm YOUR_VM
```

The command prints the path to a locally collected `summary.md`. It also writes `summary.json`, `collection.json`, sanitized object snapshots, and container logs beneath a new directory in `reports/`. No prepared inventory input is required. Existing output directories are never overwritten.

For longer history and your actual storage driver namespace:

```powershell
python troubleshoot.py --context YOUR_CONTEXT --namespace YOUR_NAMESPACE --vm YOUR_VM `
  --since 2h --tail-lines 5000 --csi-namespace YOUR_CSI_NAMESPACE `
  --output C:\Support\YOUR_NEW_REPORT_DIRECTORY
```

Repeat `--csi-namespace` for additional custom driver namespaces. This is particularly useful for PowerMax/Pure driver deployments with organization-specific labels or names. The collector examines all containers in the selected pods, including CSI driver and provisioner/attacher/resizer/snapshotter sidecars, not only the first container.

Optional kubelet journal retrieval:

```powershell
python troubleshoot.py --context YOUR_CONTEXT --namespace YOUR_NAMESPACE --vm YOUR_VM --node-journal
```

This calls `oc adm node-logs` for associated nodes. It requires privileged node-log read access; the tool does not grant that access. No node login or host filesystem execution is performed.

## What it checks

| Layer | Evidence collected |
| --- | --- |
| VM and VMI | Desired run strategy, conditions, runtime phase, referenced instancetype/preference, volumes and network attachments |
| Workload pods | VM/VMI owner relationships and PVC consumers; complete pod status, scheduling conditions, init/regular/ephemeral containers, current logs and previous logs when restart counters indicate availability |
| Storage/import | PVCs, DataVolumes, PVs, StorageClasses, CSIDrivers, selected-node CSINodes, related VolumeAttachments, importer/clone pods using those PVCs |
| CSI | Discovered driver/controller/node-plugin pods; node plugins filtered to associated nodes where detectable; custom namespaces can be supplied explicitly |
| Virtualization control plane | virt-controller, virt-handler, virt-api, virt-operator, CDI and HCO pods discovered through names/labels/container images; node-local virt-handler logs follow the VM's node |
| Nodes and admission | Node conditions, quotas, LimitRanges, storage operator, HyperConverged and KubeVirt conditions |
| Events | Recent events associated with current object UIDs; events from an older VM/pod with the same name are excluded |

CSI/component discovery is best effort. Nonstandard deployments can require explicit namespaces. Namespaces the user cannot list are recorded as missing evidence. Array-side PowerMax/Pure logs, external registry logs, guest console output, and deleted/expired container logs are not available through ordinary pod-log collection.

## How the possibilities are produced

The report evaluates structured conditions and known failure signatures for:

- VM configured as Halted/stopped rather than requesting automatic start.
- Pending PVCs, import/clone progress or failures, provisioning errors, mount errors, multi-attach and attachment failures.
- Insufficient CPU/memory/hugepages/KVM resources, affinity/topology constraints, taints and unhealthy nodes.
- Image-pull failures, missing configuration references, quota/admission/SCC rejection and Multus/CNI setup failures.
- QEMU/libvirt startup problems, unsupported CPU/KVM access, disk image or write-lock errors and OOM termination.
- Discovered controller/CSI component pods not Ready, with a separate qualification that component health is not proof of causality.

Each finding contains an evidence file/line or object field, the observed message, evidence confidence, and a suggested next investigation. **Confidence ranks the relevance of observed evidence; it is not a numerical probability or a verified root cause.** There is no external AI service or log upload.

Errors in shared controller/CSI logs are only promoted to VM-related failure hypotheses when the same line identifies the VM/namespace, a relevant object UID, a PVC, or a volume handle. Unrelated matching errors are counted separately. This reduces false attribution on busy clusters. Correlation can still miss errors where identity and error occur on different lines; inspect the collected shared logs when needed.

If no signatures are found, the report says **inconclusive**, not healthy. A currently Running VMI is distinguished from successful guest OS boot. A Pending WaitForFirstConsumer PVC is flagged for review, not automatically called a storage backend failure.

## Coverage, limits, and exit codes

Defaults: last hour, 2,000 lines and 1 MiB per container log, 80 selected pods, 300 container requests, six parallel log readers, and a ten-minute overall request deadline. Set `--since`, `--tail-lines`, `--limit-bytes`, `--max-log-pods`, `--max-log-requests`, `--workers`, and `--collection-timeout` as needed. The journal tail is limited to 100,000 lines. Requests have individual timeouts.

It cannot retrieve literally every historical log: rotation, retention, deleted pods, unavailable previous containers, RBAC, byte/line limits, and deadlines apply. Every retrieval error, absent optional object, undiscovered expected component, and budget omission is recorded in `collection.json` and summarized in the report. A successful request can still be truncated to its configured line/byte budget.

| Exit | Meaning |
| --- | --- |
| 0 | Best-effort collection completed within the configured scope; findings may be present |
| 1 | Partial evidence: permissions, API/log errors, discovery gaps or collection budgets prevented some collection |
| 2 | Fatal failure, such as inability to read the selected VM or initialize output |

The collector never retries mutations because it has no mutation operations. The `get`, `logs`, and optional `adm node-logs` commands are pinned to the explicit context. Authorization failures are not converted into healthy observations.

## Permissions and bundle handling

Use an existing diagnostic role appropriate to your environment. The tool does not install a ClusterRole or ask for cluster-admin automatically. Comprehensive collection needs:

- `get/list` VM/VMI, DataVolume, pod, event, PVC, NAD, quota and LimitRange resources in workload and relevant component namespaces.
- `get` on `pods/log` in those namespaces.
- Read access to PVs, StorageClasses, VolumeAttachments, CSIDrivers, CSINodes and associated nodes.
- Read access to HCO/KubeVirt/operator and referenced instancetype/preference resources when relevant.
- Cluster-wide pod/event list access for full discovery. If pod listing across namespaces is denied, the collector tries known virtualization/storage namespaces and any explicitly supplied CSI namespace; the original discovery gap remains visible.
- Optional node-log/proxy privileges only for `--node-journal`.

Secret objects are not queried. Common inline cloud-init data, inline environment values, last-applied annotations, credential fields, bearer tokens and private-key blocks are redacted in saved artifacts. **Redaction is best effort**: logs can contain arbitrary sensitive content and topology/identifiers remain useful diagnostic evidence. Keep the bundle private and review it before sharing. `reports/` and log files are ignored by Git.

## Development and validation

```console
python -m unittest discover -v
python troubleshoot.py --help
```

Tests cover graph traversal, current/previous container selection, CSI discovery, bounded collection, RBAC gaps, stale event UIDs, read-only command construction, secret redaction, evidence correlation, and failure classification. They use mocked API/command responses and temporary local files; no demonstration inventory is required by the operational tool. CI performs these code checks without cluster credentials.

No authenticated OpenShift lab was available during development. These checks do not certify live compatibility with every CSI driver, RBAC layout, or installed version. Start with read-only collection in your environment and review missing-evidence entries. New failure signatures should include a regression test and a precise explanation of when the message is relevant.

## Official references

- [OpenShift 4.20 virtualization support and troubleshooting](https://docs.redhat.com/en/documentation/openshift_container_platform/4.20/html/virtualization/support)
- [OpenShift 4.20 CSI documentation](https://docs.redhat.com/en/documentation/openshift_container_platform/4.20/html/storage/using-container-storage-interface-csi)
- [KubeVirt virt-handler runbook](https://kubevirt.io/monitoring/runbooks/VirtHandlerDown.html)
- [OpenShift 4.20 node-log implementation](https://github.com/openshift/oc/blob/release-4.20/pkg/cli/admin/node/logs.go)
- [MIT license](LICENSE)
