# 06: Trustee CVM unlocks on swtpm

**What to build:** a full Unlock Ceremony on the swtpm cluster, followed by Workload Attestation. The Infrastructure Operator deploys the example Trustee CVM: the helper init container and the Trustee main container, both image-pinned; Init-Data whose agent policy pins the helper's args; ConfigMaps for the Ceremony Manifest and the Sealed Bundle; one memory-backed state volume; and a helper Service with `publishNotReadyAddresses: true`. Two Security Operators run `approve` through that Service. Trustee starts with the default secure Trustee config, and a separate workload that carries Trustee's certificate in its Init-Data attests to it.

The default secure Trustee config extends ticket 05's with `storage_backend` pointed at the published tree, sessions kept in memory, and the resource policy at the backend's exact key. Record that key for ticket 10.

**Blocked by:** 05

**Status:** done

**Spec:** §1, §7, §9 Phase 0 pod checks; ADR 0002, 0007, 0008.

- [x] Operators reach the helper through its Service while the pod is not Ready, and unlock succeeds (AT-25, AT-13).
- [x] An authorized workload receives a sealed resource under the sealed policy; an unauthorized one is refused; Trustee never falls back to its built-in default policy (AT-17, AT-24).
- [x] genpolicy rejects a changed helper arg and denies exec; the memory state volume is guest-side tmpfs and survives the init-to-main handoff.
- [x] The ticket records whether guest-components can trust `kbs_cert` without the system roots. *(It can't. See Comments.)*
- [x] The helper image builds reproducibly from this repo.

## Comments

### What landed

- `deploy/examples/trustee-cvm.yaml`: the Trustee CVM pod and its two Services. The `bootstrap-helper` init container runs the helper image (`@HELPER_IMAGE@`, pinned by digest at deploy time). The `trustee` container runs the pinned KBS image with `--config-file /trustee/config/kbs.toml`. The Ceremony Manifest and the Sealed Bundle come from the ConfigMaps `trustee-ceremony-manifest` and `trustee-sealed-bundle`. One `emptyDir` with `medium: Memory` is mounted at `/trustee` in both containers, and the helper publishes into `/trustee/config`. The helper listens on 8090 and KBS on 8080. The `trustee-bootstrap-helper` Service is a NodePort with `publishNotReadyAddresses: true` and `targetPort: 8090`. The `trustee` Service is an ordinary ClusterIP, and a TCP readiness probe on 8080 makes the pod Ready once KBS listens.
- `deploy/examples/init-data.toml`: `aa.toml` and `cdh.toml` with the KBS URL `http://127.0.0.1:8081` (the helper's proxy port). genpolicy adds `policy.rego`.
- `deploy/examples/trustee-config/kbs.toml` and `verifier.DefaultTrusteeConfig(root)`: the default secure Trustee config. It is `DefaultConfig` with KBS on `0.0.0.0:8080`, `insecure_http = false`, and `private_key`/`certificate` set to `tls.key`/`tls.crt` in the tree. Like the Operator Verifier's config, it keeps `insecure_header_jwk = false`, the AS signer key and certificate with `trusted_certs_paths` listing that certificate, `AuthenticatedAuthorization` with `admin.pub`, `LocalFs` storage at `<root>/storage` (the published tree), and `session_storage_type = "Memory"`. A test decodes the example file and requires it to equal `DefaultTrusteeConfig("/trustee/config")` with no extra keys. `verifier.Config` gained the two `http_server` TLS keys.
- `cmd/bootstrap-helper/Containerfile`: a two-stage build on the pinned `golang:1.26.4-alpine` image, then `FROM scratch`. Build it with `podman build --timestamp 0 --identity-label=false`.
- `test/e2e/trustee-cvm.sh`: the end-to-end test (see below). `test/e2e/genpolicy-kind.json` is a genpolicy settings drop-in.
- `docs/upstream-pins.md`: the builder and registry images.

### The resource-policy key (for ticket 10)

KBS v0.22.0 keeps its resource policy in the storage backend under namespace `kbs`, key `resource-policy.rego` (`KBS_POLICY_ID = "resource-policy"` in `kbs/src/api_server.rs`). With `LocalFs` at `<root>/storage`, that is the file `storage/kbs/resource-policy.rego` relative to the config root: `verifier.ResourcePolicyPath`. At startup KBS writes its built-in `sample_policies/default.rego` there only if the key is absent. That default allows the `resource` plugin to any TEE whose claims have no `sample` entry, whatever the EAR status. Resources live under namespace `repository` with `/` in the key stored as `\x2F`. RVPS reference values live under `reference_value/<name>`.

### Run on the scratch VM

```sh
vmsync <worktree> t06/repo
vmssh 'cd ~/t06 && E2E_CACHE=~/t04/cache/e2e ./repo/test/e2e/kind-kata-swtpm.sh up && PATH=$HOME/sdk/go/bin:$PATH E2E_CACHE=~/t04/cache/e2e ./repo/test/e2e/trustee-cvm.sh'
```

It printed `PASS`. In order:

- **image:** the script builds the helper image twice with `--no-cache` and pushes both builds to a registry on the kind gateway. Both pushes had digest `sha256:711a051e…0074`. That digest was the same across four runs.
- **AT-25:** both Security Operators reached the helper through the NodePort of `trustee-bootstrap-helper` while the pod's Ready condition was `False`. Status went `COLLECTING []` → `[1]`, and the pod stayed not Ready with one Share.
- **AT-13:** after carol's Share, the helper published and exited 0, KBS started from the published tree, and the pod went Ready.
- **exec:** `kubectl exec` into the Trustee container failed with `ExecProcessRequest is blocked by policy`.
- **host view:** while Trustee served, the kind node's `/var/lib/kubelet/pods/<uid>/volumes/kubernetes.io~empty-dir/state` was empty.
- **AT-17:** a busybox Kata pod whose Init-Data names `https://trustee.default.svc.cluster.local:8080` and carries Trustee's certificate as `kbs_cert` (CDH) and `cert` (AA) got the sealed resource through its CDH.
- **AT-24:** a second pod with the same Init-Data plus one comment line got nothing. Its evidence is affirming (same AK, same PCR11), so KBS's built-in default would have released the resource. Only the sealed policy, which pins the first workload's PCR8, refuses it.
- **changed arg:** the same pod and Init-Data with `--proxy-port=8082` in place of `8081` never started its helper. The kubelet event for that pod UID reads `CreateContainerRequest is blocked by policy`, and its input shows the changed arg. The same pod with the original args ran earlier in the same run, so the arg alone made the difference.
- **tmpfs:** a probe pod with the same volume layout and no policy (so its logs are readable) showed the state volume in the guest as `tmpfs /state tmpfs`. A file its init container wrote reached the main container, and the host's side of the volume stayed empty.

`shellcheck -x` is clean.

### Findings

- **genpolicy works with the ticket 04 runtime class.** The coco-dev config doesn't disable the agent policy: the agent enforced the policy from Init-Data, denying exec and the changed arg. Two changes were needed, neither to Kata:
  1. A genpolicy settings drop-in (`test/e2e/genpolicy-kind.json`) sets `kata_config.oci_version` to `1.3.0`. The kind node's containerd 2.3.4 writes OCI spec 1.3.0, and genpolicy's stock settings pin `1.1.0`, so without it the policy refused even the sandbox container. Any cluster whose containerd writes another OCI version needs the matching value.
  2. genpolicy panics on `spec.automountServiceAccountToken` ("Unsupported field"), so the example pod leaves it out. The service account token mount is in genpolicy's allowed mount destinations.
- **The policy pins what spec §7 asks for.** The generated `policy.rego` pins both images by digest (`io.kubernetes.cri.image-name`), the helper's exact `Args`, and the mounts. For the state volume it requires an `ephemeral` storage with `fstype tmpfs` at `/run/kata-containers/sandbox/ephemeral/state`. `ExecProcessRequest` defaults to `false` with no allowed commands, and `ReadStreamRequest` is `false` too, so `kubectl logs` on the Trustee CVM shows nothing.
- **`emptydir_mode = "block-encrypted"` doesn't touch `medium: Memory`.** In the coco-dev config that mode applies to disk-backed `emptyDir` volumes. Kata maps a `medium: Memory` volume to an ephemeral tmpfs in the guest, as the probe showed. genpolicy's default settings assume `emptydir_type = "block-encrypted"`, which matches the runtime config.
- **The guest needs 2 GiB.** The guest pulls and unpacks both images into its own memory. With the cluster default of 1 GiB, the KBS image pull failed with `Failed to unpack layer to destination`. The example sets `io.katacontainers.config.hypervisor.default_memory: "2048"`, which the coco-dev config's `enable_annotations` allows.
- **Guest image pull from a local registry.** With `force_guest_pull`, the kubelet pulls on the node and the guest's CDH pulls again. The test registry serves plain HTTP, so the script adds a `hosts.toml` for it in the node's containerd and an `[image.registry_config]` rule with `insecure = true` to the test Init-Data's `cdh.toml`. The example Init-Data has no such rule.
- **genpolicy rewrites the Init-Data.** It reserializes the TOML (`aa.toml` and `cdh.toml` become `"""` strings) and puts `policy.rego` first. Security Operators must build their Operator Policy from the TOML in the annotation, not from the file they gave genpolicy. The script decodes the annotation into `init.toml` and runs `policy build` on that.
- **Trustee's certificate.** The script makes a self-signed leaf certificate (`CA:FALSE`, `serverAuth`, SAN `trustee.default.svc.cluster.local`). The guest's rustls client rejects a CA certificate as a server's own certificate, so the usual `openssl req -x509` certificate won't do. The guest resolved the Service's cluster DNS name.

### `kbs_cert` and the system roots (spec §1, §9 Phase 0)

guest-components v0.22.0 can't trust `kbs_cert` alone. `KbsClientBuilder::build` (`attestation-agent/kbs_protocol/src/builder.rs`) passes each configured certificate to reqwest's `add_root_certificate`, which adds a root. It never calls `tls_built_in_root_certs(false)`, and neither `aa.toml` (`[token_configs.kbs] cert`) nor `cdh.toml` (`[kbc] kbs_cert`) has a setting for it. A workload keeps trusting every system CA. This is an upstream gap. The smallest upstream change: when a KBS certificate is configured, build the client with `tls_built_in_root_certs(false)`, or add a config flag that does. Until then, Trustee's certificate must name a host no public CA will certify, as spec §1 says. The example uses `trustee.<namespace>.svc.cluster.local`.

### Not done or not proven

- **swtpm is not a TEE.** All of this proves the plumbing and the policies. It is not a real-TEE result (ticket 17). The host-side check shows only that the kubelet's directory is empty; AT-16 (the host can't read guest memory) needs a real TEE.
- **AT-24 shows the denial by behaviour.** The agent policy blocks `kubectl logs`, so the test can't read KBS's decision. It relies on the controlled pair: the two workloads differ by one Init-Data comment line, both are affirming, the first gets the resource and the second gets nothing.
- **`--manifest-sha256` is ticket 09.** The helper has no such flag yet, so the policy pins the args it has. Once ticket 09 adds the flag, the example's args must carry it.
- **CI:** ticket 07 must run `trustee-cvm.sh` on a runner, with podman as the engine. The helper image build uses `podman build --timestamp 0 --identity-label=false`, which docker lacks. Besides ticket 04's needs, it pulls the golang builder (~250 MB), the registry image and the KBS image twice (node and guest), and fetches the Kata tools tarball (~23 MB, cached in `$E2E_CACHE/out/genpolicy`).
- **Gate:** the Go gate against `trustee-bootstrap` exited 0 (gremlins found no mutable code in the change). `go vet ./...` and `go test ./...` pass.
