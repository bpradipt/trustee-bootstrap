# 14: Claim profiles for every TEE type

**What to build:** `policy build` produces a correct resource policy for every supported TEE type, not just tpm. For tdx, snp, az-snp-vtpm, az-tdx-vtpm and tpm, document at the pinned Trustee version the claim paths and types for the Init-Data digest, the digest transformation, the debug check and the required reference values. The generated policy denies when a required claim is missing.

**Blocked by:** 05

**Status:** ready-for-agent

**Spec:** §6 claim profiles, §9 Phase 3.

- [ ] A profile table cites the pinned verifier source for each TEE type.
- [ ] Each profile has fixtures for matching evidence, a wrong Init-Data digest, debug on and a missing claim; only the matching fixture gets a release (AT-28).
- [ ] Profiles without fixtures are marked untested; production Operator Policies may not accept them.
- [ ] the Go gate exits 0.
