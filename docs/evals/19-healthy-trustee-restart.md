# EV-19: Trustee container restarts inside the running CVM

**Category:** healthy path
**Runs on:** kind + swtpm; `test/e2e/golden-path.sh` runs EV-16 to EV-19
**Covers:** AT-26 (Trustee restart); spec §5 Restarts; ADR 0002

## Setup

The end state of [EV-18](18-healthy-workload-gets-key.md).

## Action

1. Stop the Trustee container on the node, as a KBS crash would. Kubelet restarts it in the same pod sandbox, so the CVM keeps running:

   ```sh
   id=$(kubectl get pod trustee-cvm -o jsonpath='{.status.containerStatuses[0].containerID}')
   crictl stop "${id#containerd://}"     # on the node
   ```

2. Wait until the pod is Ready with one restart.
3. Run `workload-ok` from EV-18 again, as `workload-again`.

## Expected

```text
$ kubectl get pod trustee-cvm
NAME          READY   STATUS    RESTARTS     AGE
trustee-cvm   1/1     Running   1 (4s ago)   91s

$ kubectl get pod trustee-cvm -o jsonpath='{.status.podIP}'
<the same pod-ip as the trustee endpoint in EV-17>

$ kubectl get pod trustee-cvm -o jsonpath='{.status.initContainerStatuses[0].restartCount} {.status.initContainerStatuses[0].state.terminated.reason}'
0 Completed

$ kubectl get events --field-selector involvedObject.name=trustee-cvm --sort-by=.lastTimestamp \
    -o custom-columns=TYPE:.type,REASON:.reason,OBJECT:.involvedObject.fieldPath,COUNT:.count,MESSAGE:.message
... (the EV-17 events, then:)
Normal    Created     spec.containers{trustee}   2   Container created
Normal    Pulled      spec.containers{trustee}   1   Container image "ghcr.io/confidential-containers/key-broker-service:built-in-as-v0.22.0@sha256:c1960cb4..." already present on machine and can be accessed by the pod
Normal    Started     spec.containers{trustee}   2   Container started

$ trustee-bootstrap status --endpoint "$ENDPOINT"
Error: get status: Get "<endpoint>/bootstrap/v1/status": dial tcp <node-ip>:<node-port>: connect: connection refused

$ kubectl logs workload-again
trustee-workload-ok
```

The eval passes when:

- The pod is `1/1 Running` with one restart, and its IP hasn't changed. Kubelet kept the sandbox.
- The bootstrap-helper init container still shows 0 restarts and `Completed`. It didn't run again, and `status` still refuses connections.
- `workload-again` gets `trustee-workload-ok` with no new Unlock Ceremony.

## Notes

The restarted Trustee finds its config because the state volume belongs to the pod sandbox, the CVM, and not to the container. It is a tmpfs in guest memory, and it lives as long as the VM. The new KBS process reads the tree the helper published. If the helper ever ran again in the same sandbox, it would find the completion marker and exit 0 (AT-26 "after").

Anything that ends the VM wipes the tree: pod deletion, eviction, a node reboot, or a dead QEMU process. The next boot starts in LOCKED and needs a new Unlock Ceremony. [EV-11](11-pod-recreation-after-unlock.md) covers those cases.

The host can trigger this restart, but the agent policy in Init-Data lets only the same pinned image with the same args start, and it denies exec. The tree never leaves guest memory.

## Results

- 2026-11-12, `6057ad8`, scratch VM (kind + Kata 4.2.0 + swtpm, 4 vCPU, 6 GB): **pass**. The output above comes from this run.
