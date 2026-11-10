# 06: Trustee CVM unlocks on swtpm

**What to build:** a full Unlock Ceremony on the swtpm cluster, followed by Workload Attestation. The Infrastructure Operator deploys the example Trustee CVM: the helper init container and the Trustee main container, both image-pinned; Init-Data whose agent policy pins the helper's args; ConfigMaps for the Ceremony Manifest and the Sealed Bundle; one memory-backed state volume; and a helper Service with `publishNotReadyAddresses: true`. Two Security Operators run `approve` through that Service. Trustee starts with the default secure Trustee config, and a separate workload that carries Trustee's certificate in its Init-Data attests to it.

The default secure Trustee config extends ticket 05's with `storage_backend` pointed at the published tree, sessions kept in memory, and the resource policy at the backend's exact key. Record that key for ticket 10.

**Blocked by:** 05

**Status:** ready-for-agent

**Spec:** §1, §7, §9 Phase 0 pod checks; ADR 0002, 0007, 0008.

- [ ] Operators reach the helper through its Service while the pod is not Ready, and unlock succeeds (AT-25, AT-13).
- [ ] An authorized workload receives a sealed resource under the sealed policy; an unauthorized one is refused; Trustee never falls back to its built-in default policy (AT-17, AT-24).
- [ ] genpolicy rejects a changed helper arg and denies exec; the memory state volume is guest-side tmpfs and survives the init-to-main handoff.
- [ ] The ticket records whether guest-components can trust `kbs_cert` without the system roots.
- [ ] The helper image builds reproducibly from this repo.
