# 06 Claim profiles per TEE type

Status: open
Type: spike
Blocked by: 01

## What

Write the claim-profile table that `policy build` (ticket 12) implements. For each TEE type (tdx, snp, az-snp-vtpm, az-tdx-vtpm, tpm), record at the pinned Trustee version: the EAR claim paths and types for the Init-Data digest, the digest transformation (for example PCR8 = `sha256(0³² ‖ digest)`), the debug check, and the reference values required.

## Spec

`IMPLEMENTATION_SPEC.md` §6 (claim profiles), §9 Phase 0 and Phase 3, AT-28.

## Done when

- [ ] `docs/claim-profiles.md` holds the table, citing pinned source lines.
- [ ] Positive and negative evidence fixtures exist for each profile (matching, wrong Init-Data digest, debug on, a required claim missing), at least for tpm. Mark any profile without fixtures as untested.
