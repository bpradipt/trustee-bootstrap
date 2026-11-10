# 11 policy build

Status: open
Type: task
Blocked by: 05, 06, 07

## What

`pkg/policy/` and the `policy build` command. Inputs: a reviewed Init-Data TOML, a reference-values file, the accepted TEE types, the Approved Bundle digest, the manifest and the operator's Share file. Output: the Operator Policy plus the generated Operator Verifier KBS config (from the ticket 05 template), resource policy rego and RVPS values.

- Compute the Init-Data digest from the TOML; never take a pasted hash.
- Generate the resource policy from the claim profiles (ticket 06). Deny when any required claim is missing.

## Spec

`IMPLEMENTATION_SPEC.md` §3 item 6, §6 (`policy build`, claim profiles).

## Done when

- [ ] The computed Init-Data digest matches what the ticket 02 environment reports.
- [ ] The generated policy passes ticket 06's fixtures (AT-28) for every profile that has fixtures.
- [ ] the Go gate exits 0.
