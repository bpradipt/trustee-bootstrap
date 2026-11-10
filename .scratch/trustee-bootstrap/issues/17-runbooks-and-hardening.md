# 17 Runbooks and supply-chain hardening

Status: open
Type: task
Blocked by: 15

## What

- Redacted audit events from the helper and CLI.
- Runbooks: the Key Ceremony, sealing on a controlled machine and destroying the plaintext (ADR 0008), the Unlock Ceremony, withdrawing an approval by restarting the CVM, Trustee upgrades, and roster change by a fresh Key Ceremony.
- SBOM, dependency pinning, and no test-only flags on the production path.

## Spec

`IMPLEMENTATION_SPEC.md` §9 Phase 3; `SECURITY_THREAT_MODEL.md` residual risks.

## Done when

- [ ] Each runbook exists under `docs/runbooks/`.
- [ ] The release build has an SBOM and pinned dependencies.
