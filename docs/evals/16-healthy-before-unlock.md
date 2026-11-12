# EV-16: Deployed Trustee CVM waits for Shares

**Category:** healthy path
**Runs on:** kind + swtpm; `test/e2e/golden-path.sh` runs EV-16 to EV-19
**Covers:** AT-25; [unlock-ceremony.md](../runbooks/unlock-ceremony.md) part 1 step 7 and part 3 step 1; spec §7 Services
**Next:** [EV-17](17-healthy-unlock.md) starts where this eval ends.

## Setup

A 2-of-3 Key Ceremony, a Sealed Bundle and a rendered pod with its Init-Data: the Unlock Ceremony runbook's part 1, steps 1 to 6. `test/e2e/trustee-cvm.sh` does the same on the e2e cluster, up to its `deploy` step.

## Action

Apply `trustee-cvm.yaml` (part 1, step 7) and wait until `status` answers. Then run each command below.

## Expected

Values in `<angle brackets>` change from run to run.

```text
$ kubectl get pod trustee-cvm
NAME          READY   STATUS     RESTARTS   AGE
trustee-cvm   0/1     Init:0/1   0          8s

$ kubectl get service trustee-bootstrap-helper trustee
NAME                       TYPE        CLUSTER-IP     EXTERNAL-IP   PORT(S)                AGE
trustee-bootstrap-helper   NodePort    <cluster-ip>   <none>        8090:<node-port>/TCP   9s
trustee                    ClusterIP   <cluster-ip>   <none>        8080/TCP               9s

$ kubectl get endpoints trustee-bootstrap-helper trustee
Warning: v1 Endpoints is deprecated in v1.33+; use discovery.k8s.io/v1 EndpointSlice
NAME                       ENDPOINTS         AGE
trustee-bootstrap-helper   <pod-ip>:8090     9s
trustee                                      8s

$ trustee-bootstrap status --endpoint "$ENDPOINT"
{
  "boot_id": "<26 base32 characters>",
  "key_id": "<32 hex characters>",
  "state": "COLLECTING",
  "threshold": 2,
  "accepted": [],
  "rejected": []
}
```

The eval passes when:

- The pod shows `0/1`, `Init:0/1` and `0` restarts: the bootstrap-helper init container runs, and Trustee waits for it.
- `trustee-bootstrap-helper` lists the pod's IP on port 8090 while the pod isn't Ready. Its Service publishes not-ready addresses (AT-25).
- `trustee` lists no endpoint, so no workload can reach Trustee yet.
- `status` shows the `key_id` from `ceremony.json`, `COLLECTING`, threshold 2, and empty `accepted` and `rejected` lists.

## When it looks different

- `Init:Error` or `Init:CrashLoopBackOff`, and `status` never answers: the mounted `ceremony.json` doesn't match `--manifest-sha256`, or the bundle is over 1 MiB (AT-11).
- The pod stays `Init:0/1` and `kubectl get events` shows `CreateContainerRequest is blocked by policy`: the rendered pod and its Init-Data disagree. Run genpolicy again.
- `trustee-bootstrap-helper` has no endpoint: the Service lost `publishNotReadyAddresses: true`.

## Results

- 2026-11-12, `6057ad8`, scratch VM (kind + Kata 4.2.0 + swtpm, 4 vCPU, 6 GB): **pass**. The output above comes from this run.
