# 02 kind + Kata + swtpm environment for dev and CI

Status: open
Type: spike
Blocked by: 01

## What

Stand up the environment that CI and local development both use: a kind cluster with Kata Containers, guest images whose AA uses the TPM attester backed by swtpm, all at the pinned versions. Script it, so CI and a laptop run the same thing.

## Spec

`IMPLEMENTATION_SPEC.md` §9 Phase 0 (swtpm item); §7 Platforms. TPM was chosen for CI because it is cheap and exercises the whole flow.

## Done when

- [ ] One script (for example `test/e2e/env/up.sh`) brings the environment up on a KVM-capable Linux host and in a CI runner.
- [ ] A test pod's AA produces TPM evidence, and the pinned Trustee TPM verifier accepts it.
- [ ] The Init-Data digest appears in the verifier's claims (expected: PCR8 = `sha256(0³² ‖ digest)`).
- [ ] Notes record what the TPM verifier requires for AK/EK trust.
