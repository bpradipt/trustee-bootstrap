# 04: Kata + swtpm environment

**What to build:** one script that brings up the cluster that both CI and developer laptops use. It runs kind with Kata Containers at the pinned versions, and the guest AA uses the TPM attester backed by swtpm. TPM was chosen for CI because it is cheap and exercises the whole flow.

**Blocked by:** 01

**Status:** done

**Spec:** §7 Platforms, §9 Phase 0.

- [ ] The same script works on a KVM-capable Linux host and in a CI runner. *(KVM host: yes. CI runner: not run. Ticket 07 added the workflow, but the repo has no remote to run it on. See Comments.)*
- [x] A test pod's AA produces TPM evidence that the pinned Trustee TPM verifier accepts.
- [x] The Init-Data digest shows in the verifier's claims (expected: PCR8 = `sha256(0³² ‖ digest)`).
- [x] The ticket records what the TPM verifier requires for AK/EK trust.

## Comments

### What the script does

`test/e2e/kind-kata-swtpm.sh up | verify | down`. Every step is idempotent, and built artifacts are cached in `$E2E_CACHE` (default `~/.cache/trustee-bootstrap-e2e`). Pins are in `docs/upstream-pins.md`, including a new "swtpm test environment" table.

Stock Kata 4.2.0 can't run the TPM attester. Three pieces are missing, and the script supplies each one without patching upstream:

1. **Guest kernel.** The 4.2.0 guest kernel has no TPM driver. The script rebuilds it with Kata's own `build-kernel.sh` and fragments at the pinned commit, with the same flags as `kata-deploy-binaries.sh` (`-x -m`), and adds `test/e2e/kernel-tpm.conf` (`TCG_TPM`, `TCG_TIS`, `TCG_CRB`). It takes about 12 minutes on 4 vCPUs.
2. **Attestation Agent.** The pinned coco-extension AA has only the snp and tdx attesters. The script builds the pinned AA with `ATTESTER=tpm-attester` in an `ubuntu:26.04` container, the guest's release, and copies its tss2 and openssl libraries next to it. It then puts that AA into the pinned coco-extension payload, sets `LD_LIBRARY_PATH` in `components.toml`, and packs the result with guest-components' own `build-erofs-image.sh`. The image stays dm-verity measured. The build takes about 7 minutes, and nothing but the binary and its libraries leaves the container.
3. **vTPM.** Kata has no swtpm option, and the QEMU in kata-static is built without TPM support (`-tpmdev: invalid option`). The runtime class therefore uses the kind node's Debian QEMU, through the wrapper `test/e2e/qemu-swtpm` set as the hypervisor `path`. For each pod VM, the wrapper copies a provisioned swtpm state, starts swtpm on a unix socket, and adds `-tpmdev emulator` and `-device tpm-crb`.

From the pinned `kata-static-4.2.0-amd64.tar.zst`, the script takes only three files: the runtime-rs shim, the Ubuntu base image and the `qemu-coco-dev-runtime-rs` config. The config gets the wrapper, the TPM kernel, our extension and its verity parameters, `default_memory = 1024` (`E2E_GUEST_MEMORY_MB`), and `experimental = ["force_guest_pull"]`, so no nydus snapshotter is needed. The containerd runtime and the RuntimeClass are both named `kata-qemu-coco-dev-tpm`, and `pod_annotations = ["io.katacontainers.*"]` lets `cc_init_data` through. The kind node also needs a D-Bus daemon, because the runtime-rs shim places the sandbox cgroup through systemd.

`verify` runs the pinned KBS image on the host, bound to the kind gateway, with a test-only config: plain HTTP, an open admin API and `insecure_header_jwk = true`. Ticket 05 owns the secure config. `verify` then loads the AK and PCR11 into RVPS, loads `test/e2e/resource-policy.rego`, and starts two busybox pods whose CDH fetch a resource:

- **Matching Init-Data:** the resource is released. The claims carry `init_data = 07c16dce…bbdb`, and that equals `sha256(0³² ‖ sha256(Init-Data TOML))`, computed on the host.
- **Changed Init-Data** (one comment line added): the verifier still accepts the evidence, because PCR8 matches the Init-Data that this AA sent. The resource policy denies it. The claim shows the new PCR8.

### Run on the scratch VM (4 vCPU, 6 GB, nested KVM, rootful podman)

```sh
vmsync <worktree> t04/repo
vmssh 'cd ~/t04 && E2E_CACHE=~/t04/cache/e2e ./repo/test/e2e/kind-kata-swtpm.sh up && E2E_CACHE=~/t04/cache/e2e ./repo/test/e2e/kind-kata-swtpm.sh verify'
```

The last run did `down`, then `up` (1 min 35 s, with cached builds), a second `up` (a no-op), and `verify`, which printed `PASS`. Package versions in the kind node (Debian 13): qemu-system-x86 `1:10.0.13+ds-0+deb13u1`, swtpm `0.7.1-1.5`, tpm2-tools `5.7-1`. `shellcheck` is clean. No Go changed, so the Go gate does not apply.

### AK/EK trust in the pinned TPM verifier (Trustee v0.22.0)

- **EK:** not checked at all. The evidence carries no EK and no EK certificate. The swtpm template is made with `swtpm_setup --createek`, without certificates, only because the AK must be created under an EK.
- **AK:** the verifier checks only that the quote is signed by the AK the guest itself sends (`ak_public`). It does not judge whether that AK is trusted. Trust comes from the AS policy alone. The default policy (`ear_default_policy_cpu.rego`) sets `executables = 3` only if `input.tpm.ak_public in query_reference_value("trusted_aks")` and `input.tpm.pcr11 in query_reference_value("tpm_pcr11")`. The reference value is named **`trusted_aks`**. The verifier README says `trusted_ak`, which is wrong for the default policy.
- **Format:** `ak_public` is base64 of the DER SubjectPublicKeyInfo. That is the body of the PEM from `tpm2_createak -f pem`, and the script uses it as is.
- **Tested both ways:** with the AK in `trusted_aks`, the status is `affirming`. Without it, the verifier still passes ("Verifier/endorsement check passed. tee=Tpm"), but `executables = 33` and the status is `warning`, so a policy that requires `affirming` denies. A resource policy that skips the `ear.status` check releases to any AK, including one from an swtpm the attacker set up. The tpm claim profile (ticket 05) must require `affirming` and a `trusted_aks` entry.
- **Other checks the verifier does:** PCR digest against the quote, nonce, and PCR8 = `sha256(0³² ‖ init_data_hash)`. The KBS report data is 48 bytes, and the TPM attester truncates it to 32. The verifier truncates the expected value the same way, so only the first 32 bytes are bound.
- **Where the claims are:** in the EAR token, `init_data` and `report_data` move to the top of `ear.veraison.annotated-evidence`. They are not under `.tpm`. `.tpm` holds `ak_public` and `pcr00`…`pcr23`. PCR11 is all zeros in this guest. The parsed Init-Data is under `init_data_claims`.
- **The AK is shared.** Every pod VM starts from a copy of one swtpm state, so all pods share one AK and the cluster trusts it. That is fine for CI. It also means the AK proves nothing about which VM is talking.

### For later tickets

- **Init-Data must use `algorithm = "sha256"`.** The AA extends the sha256 PCR bank with the raw digest. `aa.toml` must contain `[eventlog_config]` (`init_pcr`, `enable_eventlog`), because the AA refuses a config without it.
- `kubectl` runs inside the node: `<engine> exec <cluster>-control-plane kubectl --kubeconfig /etc/kubernetes/admin.conf`. With podman, kind runs under `sudo`.
- The stock config sets `emptydir_mode = "block-encrypted"`. Ticket 06's `medium: Memory` check should look at that.

### Not done

- **CI runner.** Not run. A runner needs `/dev/kvm` (nested virtualization when the runner is itself a VM), a rootful docker or podman, `sudo`, `apt-get`, internet access to github.com, ghcr.io, docker.io and kernel.org, and about 8 GB of free disk for the first build. About 20 minutes of the first run is building the kernel and the AA. Cache `$E2E_CACHE/out` between runs. GitHub-hosted Ubuntu runners have `/dev/kvm`, but nobody has run this script on one. Ticket 07 must prove it.
- The wrapper leaves each finished VM's swtpm state (a few KiB) under `/run/kata-swtpm` in the node.
- The kernel, AA and extension are built locally, so they are not byte-for-byte reproducible from a digest the way the pinned images are. Their sources are pinned by tag and commit, and the script checks the commit.
