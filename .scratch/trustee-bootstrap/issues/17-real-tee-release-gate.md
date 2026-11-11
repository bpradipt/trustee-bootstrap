# 17: Real-TEE release gate

**What to build:** the go/no-go decision from the threat model. Repeat the ticket 06 ceremony and the full acceptance suite on at least one real TEE (TDX, SNP or Azure vTPM). Swtpm results never count towards this gate.

**Blocked by:** 07, 08, 09, 10, 11, 12, 13, 14, 15, 16

**Status:** ready-for-agent

**Spec:** §9 Phase 3, §11; threat model go/no-go.

- [ ] Every acceptance test passes on the real TEE, including AT-16.
- [ ] That TEE's claim profile is marked tested.
- [ ] Security review notes record the actual trust roots, measurements and residual risks.
- [ ] The run sets the attestation collateral source (Intel PCS or a PCCS, AMD KDS, or offline files) through Trustee's own settings in the generated Operator Verifier config (`pkg/verifier` `DefaultConfig`), and records which one it used. Today that config sets none (`docs/claim-profiles.md`, Attestation collateral).
