# EV-14: Broken sealed resource policy

**Category:** partial failure
**Runs on:** kind + swtpm; `test/e2e/evals-cluster.sh ev14`
**Covers:** the open Phase 0 item in spec §9; threat "unlocked Trustee runs its built-in default policy"; invariant 7; AT-24; sealed-config check 3 (spec §3)

## Setup

A tree from the seal runbook whose `storage/kbs/resource-policy.rego` has a syntax error, such as an unclosed brace. The file exists, isn't empty and differs from KBS's default, so `seal` accepts it. Seal it, deploy it, and unlock with two Shares.

## Action

`workload-ok` and `workload-other` request their resources, as in AT-24.

## Expected

- Trustee refuses both requests.
- `workload-other` gets nothing. KBS's built-in default policy would release to it, because it releases every resource to any attested non-sample TEE.
- Record whether the helper exits 0 and whether Trustee becomes Ready.

## Notes

Ticket 14 saw the pinned KBS deny every request when it couldn't load a policy, outside a CVM. If KBS falls back to its default inside the Trustee CVM, sealed-config check 3 must parse the Rego, and `seal` and the helper must refuse this bundle.

## Results

- 2026-11-12, branch `evals-rest`, scratch VM (kind + Kata 4.2.0 + swtpm), `test/e2e/evals-cluster.sh`: **pass**. `seal` accepted the broken policy, the helper published it and exited 0, and Trustee became Ready. Trustee refused both workloads. KBS doesn't fall back to its built-in default, which closes a Phase 0 item in spec §9.
