# 16: Runbooks and supply chain

**What to build:** the people who run this have written procedures, and the release is traceable. Runbooks cover:
- the Key Ceremony;
- sealing on a controlled machine and destroying the plaintext afterwards;
- the Unlock Ceremony;
- withdrawing an approval by restarting the CVM;
- Trustee upgrades;
- roster change through a fresh Key Ceremony.

The helper and CLI emit redacted audit events. The release ships an SBOM and pinned dependencies, with no test-only flags on the production path.

**Blocked by:** 06

**Status:** ready-for-agent

**Spec:** §9 Phase 3; ADR 0008; threat model residual risks.

- [ ] Each runbook exists and a second person can follow it without asking questions.
- [ ] The release build includes an SBOM.
