# 04 Spike: pod-level guarantees

Status: open
Type: spike
Blocked by: 02

## What

Confirm the Kubernetes and Kata behaviour the design relies on, in the ticket 02 environment.

## Spec

`IMPLEMENTATION_SPEC.md` §1 (kbs_cert note), §7, §9 Phase 0; ADR 0007.

## Done when

- [ ] genpolicy pins the helper container's args (including `--manifest-sha256`), so a changed value is rejected. Record that a dropped arg is allowed, which is why the helper must fail closed.
- [ ] The generated policy denies exec and extra containers.
- [ ] An `emptyDir` with `medium: Memory` is a tmpfs inside the guest, and it survives the init-to-main container handoff.
- [ ] A Service with `publishNotReadyAddresses: true` routes to the init container while the pod is not Ready.
- [ ] Record whether guest-components can trust `kbs_cert` without the system roots. If it can't, note it as an upstream gap.
