# 04: Kata + swtpm environment

**What to build:** one script that brings up the cluster that both CI and developer laptops use. It runs kind with Kata Containers at the pinned versions, and the guest AA uses the TPM attester backed by swtpm. TPM was chosen for CI because it is cheap and exercises the whole flow.

**Blocked by:** 01

**Status:** ready-for-agent

**Spec:** §7 Platforms, §9 Phase 0.

- [ ] The same script works on a KVM-capable Linux host and in a CI runner.
- [ ] A test pod's AA produces TPM evidence that the pinned Trustee TPM verifier accepts.
- [ ] The Init-Data digest shows in the verifier's claims (expected: PCR8 = `sha256(0³² ‖ digest)`).
- [ ] The ticket records what the TPM verifier requires for AK/EK trust.
