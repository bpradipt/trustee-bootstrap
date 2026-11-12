# EV-18: A CoCo workload gets a key from the unlocked Trustee

**Category:** healthy path
**Runs on:** kind + swtpm; `test/e2e/golden-path.sh` runs EV-16 to EV-19
**Covers:** AT-17, AT-24; spec §1 (how workloads trust Trustee); spec §7 state volume
**Next:** [EV-19](19-healthy-trustee-restart.md) starts where this eval ends.

## Setup

- The end state of [EV-17](17-healthy-unlock.md).
- The sealed tree held:
  - the resource `default/e2e/secret` with the value `trustee-workload-ok`, in the file `storage/repository/default\x2Fe2e\x2Fsecret`;
  - the resource policy `test/e2e/resource-policy.rego`, which releases a resource only to affirming TPM evidence whose PCR8 holds the authorized workload's Init-Data digest. The e2e computes it with `pcr8_for` in `test/e2e/kind-kata-swtpm.sh`: `sha256(32 zero bytes ‖ sha256(Init-Data TOML))`.
- The authorized workload's Init-Data. `<tls.crt>` is Trustee's certificate from the seal runbook:

  ```toml
  version = "0.1.0"
  algorithm = "sha256"
  [data]
  "aa.toml" = '''
  [eventlog_config]
  init_pcr = 17
  enable_eventlog = false
  [token_configs.kbs]
  url = "https://trustee.default.svc.cluster.local:8080"
  cert = """
  <tls.crt>
  """
  '''
  "cdh.toml" = '''
  socket = "unix:///run/confidential-containers/cdh.sock"
  credentials = []
  [kbc]
  name = "cc_kbc"
  url = "https://trustee.default.svc.cluster.local:8080"
  kbs_cert = """
  <tls.crt>
  """
  '''
  ```

  The unauthorized workload uses the same file with one more line, `# another workload`, so its digest differs.

## Action

Apply this pod, with the annotation set to `gzip -9 | base64 -w0` of the Init-Data, and wait for it to finish:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: workload-ok
  annotations:
    io.katacontainers.config.hypervisor.cc_init_data: "<gzip+base64 Init-Data>"
spec:
  runtimeClassName: kata-qemu-coco-dev-tpm
  restartPolicy: Never
  containers:
  - name: probe
    image: docker.io/library/busybox:1.37.0@sha256:a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec
    command: ["sh", "-c", "wget -qO- http://127.0.0.1:8006/cdh/resource/default/e2e/secret 2>/dev/null || echo DENIED"]
```

```sh
kubectl wait --for=jsonpath='{.status.phase}'=Succeeded pod/workload-ok --timeout=300s
```

Then do the same as `workload-other` with the unauthorized Init-Data.

## Expected

```text
$ kubectl get pod workload-ok
NAME          READY   STATUS      RESTARTS   AGE
workload-ok   0/1     Completed   0          19s

$ kubectl logs workload-ok
trustee-workload-ok

$ kubectl get events --field-selector involvedObject.name=workload-ok --sort-by=.lastTimestamp \
    -o custom-columns=TYPE:.type,REASON:.reason,OBJECT:.involvedObject.fieldPath,MESSAGE:.message
TYPE     REASON      OBJECT                   MESSAGE
Normal   Scheduled   <none>                   Successfully assigned default/workload-ok to <node>
Normal   Pulling     spec.containers{probe}   Pulling image "docker.io/library/busybox:1.37.0@sha256:a7dbc319..."
Normal   Pulled      spec.containers{probe}   Successfully pulled image "..." in 6.237s (6.237s including waiting). Image size: 2222118 bytes.
Normal   Created     spec.containers{probe}   Container created
Normal   Started     spec.containers{probe}   Container started

$ kubectl get pod workload-other
NAME             READY   STATUS      RESTARTS   AGE
workload-other   0/1     Completed   0          13s

$ kubectl logs workload-other
DENIED
```

The eval passes when:

- `workload-ok` completes and prints exactly `trustee-workload-ok`. Its CDH attested to Trustee over TLS, trusting `kbs_cert`, and Trustee released the sealed resource under the sealed policy (AT-17).
- `workload-other` completes and prints `DENIED`. Trustee runs the sealed policy, not KBS's built-in default, which would release to any attested non-sample TEE (AT-24).
- Neither pod has a Warning event.

## Notes

The probe asks its CDH for the resource over the guest-local API on port 8006. Real workloads reach Trustee the same way, or through sealed secrets or encrypted images, which this eval doesn't cover.

## Results

- 2026-11-12, `6057ad8`, scratch VM (kind + Kata 4.2.0 + swtpm, 4 vCPU, 6 GB): **pass**. The output above comes from this run.
