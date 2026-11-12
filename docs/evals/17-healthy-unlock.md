# EV-17: Two Security Operators unlock Trustee

**Category:** healthy path
**Runs on:** kind + swtpm; `test/e2e/golden-path.sh` runs EV-16 to EV-19
**Covers:** AT-03, AT-13, AT-16 (host side only); [unlock-ceremony.md](../runbooks/unlock-ceremony.md) parts 2 and 3; the audit records in the [runbooks README](../runbooks/README.md); spec §5
**Next:** [EV-18](18-healthy-workload-gets-key.md) starts where this eval ends.

## Setup

- The end state of [EV-16](16-healthy-before-unlock.md).
- Alice (index 1) and Carol (index 3) each built an Operator Policy with `policy build`. Each printed the same digest:

  ```text
  init_data_sha256 <64 hex characters>
  ```

## Action

1. Alice runs `approve`, then `status`, then `kubectl get pod trustee-cvm`.
2. Carol runs `approve`, then `status`.
3. Run the remaining commands below.

## Expected

Values in `<angle brackets>` change from run to run.

### Alice approves

`approve` writes a warning and the audit records to stderr, and `accepted` to stdout:

```text
$ trustee-bootstrap approve --endpoint "$ENDPOINT" --policy ~/trustee-policy --share-file alice.share
warning: this Operator Policy accepts untested claim profiles; it is not a production Operator Policy
{"time":"<t>","level":"INFO","msg":"verifier_started","index":1,"key_id":"<key_id>","endpoint":"<endpoint>","address":"127.0.0.1:<port>"}
{"time":"<t>","level":"INFO","msg":"relay_opened","index":1,"key_id":"<key_id>","endpoint":"<endpoint>"}
{"time":"<t>","level":"INFO","msg":"relay_closed","index":1,"key_id":"<key_id>","endpoint":"<endpoint>","code":1000}
{"time":"<t>","level":"INFO","msg":"verifier_stopped","index":1,"key_id":"<key_id>","endpoint":"<endpoint>"}
{"time":"<t>","level":"INFO","msg":"approve_result","index":1,"key_id":"<key_id>","endpoint":"<endpoint>","accepted":true}
accepted

$ trustee-bootstrap status --endpoint "$ENDPOINT"
{
  "boot_id": "<same as in EV-16>",
  "key_id": "<key_id>",
  "state": "COLLECTING",
  "threshold": 2,
  "accepted": [
    1
  ],
  "rejected": []
}

$ kubectl get pod trustee-cvm
NAME          READY   STATUS     RESTARTS   AGE
trustee-cvm   0/1     Init:0/1   0          13s
```

### Carol approves

Carol's `approve` prints the same records with `"index":3`, then `accepted`. The helper publishes and exits within a second, so `status` stops answering:

```text
$ trustee-bootstrap status --endpoint "$ENDPOINT"
Error: get status: Get "<endpoint>/bootstrap/v1/status": dial tcp <node-ip>:<node-port>: connect: connection refused

$ kubectl wait --for=condition=Ready pod/trustee-cvm --timeout=600s
pod/trustee-cvm condition met

$ kubectl get pod trustee-cvm
NAME          READY   STATUS    RESTARTS   AGE
trustee-cvm   1/1     Running   0          42s

$ kubectl get pod trustee-cvm -o jsonpath='{.status.initContainerStatuses[0].state.terminated}'
{"containerID":"containerd://<id>","exitCode":0,"finishedAt":"<t>","reason":"Completed","startedAt":"<t>"}

$ kubectl get endpoints trustee-bootstrap-helper trustee
Warning: v1 Endpoints is deprecated in v1.33+; use discovery.k8s.io/v1 EndpointSlice
NAME                       ENDPOINTS         AGE
trustee-bootstrap-helper   <pod-ip>:8090     47s
trustee                    <pod-ip>:8080     46s

$ kubectl get events --field-selector involvedObject.name=trustee-cvm --sort-by=.lastTimestamp \
    -o custom-columns=TYPE:.type,REASON:.reason,OBJECT:.involvedObject.fieldPath,MESSAGE:.message
TYPE      REASON      OBJECT                                  MESSAGE
Normal    Scheduled   <none>                                  Successfully assigned default/trustee-cvm to <node>
Normal    Pulling     spec.initContainers{bootstrap-helper}   Pulling image "<registry>/trustee-bootstrap/bootstrap-helper@sha256:<digest>"
Normal    Pulled      spec.initContainers{bootstrap-helper}   Successfully pulled image "..." in 1.233s (1.233s including waiting). Image size: 3343230 bytes.
Normal    Created     spec.initContainers{bootstrap-helper}   Container created
Normal    Started     spec.initContainers{bootstrap-helper}   Container started
Normal    Pulling     spec.containers{trustee}                Pulling image "ghcr.io/confidential-containers/key-broker-service:built-in-as-v0.22.0@sha256:c1960cb4..."
Normal    Pulled      spec.containers{trustee}                Successfully pulled image "..." in 14.322s (14.322s including waiting). Image size: 115407491 bytes.
Normal    Created     spec.containers{trustee}                Container created
Normal    Started     spec.containers{trustee}                Container started
Warning   Unhealthy   spec.containers{trustee}                Readiness probe failed: dial tcp <pod-ip>:8080: connect: connection refused

$ kubectl logs trustee-cvm -c bootstrap-helper

$ kubectl logs trustee-cvm -c trustee

$ kubectl exec trustee-cvm -c trustee -- true
error: Internal error occurred: ... rpc status: Status { code: PERMISSION_DENIED, message: "\"ExecProcessRequest is blocked by policy: ...
```

On the node, the host side of the state volume is empty:

```text
$ ls -A /var/lib/kubelet/pods/<pod-uid>/volumes/kubernetes.io~empty-dir/state
$
```

The eval passes when:

- Each `approve` exits 0 and prints `accepted`. Its audit records run `verifier_started`, `relay_opened`, `relay_closed` with code `1000`, `verifier_stopped`, `approve_result` with `"accepted":true`, and carry no Share, JWE, token or key.
- After Alice, `status` keeps the same `boot_id` and shows `accepted: [1]`, and the pod stays `Init:0/1`.
- After Carol, `status` refuses connections, and the init container ended with exit code 0 and reason `Completed`.
- The pod reaches `1/1 Running` with 0 restarts, and `trustee` lists the pod's IP on port 8080.
- The only Warning event is one `Unhealthy` readiness failure while KBS starts.
- `kubectl logs` prints nothing for either container, because the agent policy denies `ReadStreamRequest`.
- `kubectl exec` fails with `ExecProcessRequest is blocked by policy`.
- The host side of the state volume is empty.

## Notes

- The untested-profiles warning appears because the swtpm policy needs `--allow-untested-profiles`. A production Operator Policy, after ticket 17, prints no warning.
- `trustee-bootstrap-helper` keeps its endpoint after the unlock, because the Service publishes not-ready addresses. Nothing listens on port 8090 any more.
- In this run, Alice's `approve` took 1.3 s and Carol's 0.9 s. Trustee was Ready about 30 s after the pod started, most of it the 14 s KBS image pull inside the guest.

## Results

- 2026-11-12, `6057ad8`, scratch VM (kind + Kata 4.2.0 + swtpm, 4 vCPU, 6 GB): **pass**. The output above comes from this run.
