# 18 Real-TEE release gate

Status: open
Type: task
Blocked by: 15, 17

## What

Repeat ticket 15 on at least one real TEE (TDX, SNP or Azure vTPM). This is the go/no-go in `SECURITY_THREAT_MODEL.md`. Swtpm results never count towards it.

## Spec

`IMPLEMENTATION_SPEC.md` §9 Phase 3, §11; `SECURITY_THREAT_MODEL.md` go/no-go.

## Done when

- [ ] Every acceptance test passes on the real TEE, including AT-16.
- [ ] That TEE's claim profile is marked tested in `docs/claim-profiles.md`; production Operator Policies accept only tested profiles.
- [ ] Security review notes record the actual trust roots, measurements and residual risks.
