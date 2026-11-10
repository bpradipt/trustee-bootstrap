# 15 End-to-end on swtpm, in CI

Status: open
Type: task
Blocked by: 02, 13, 14

## What

`test/e2e/`: in the ticket 02 environment, two Security Operators unlock a 2-of-3 Trustee CVM through the helper's Service. Trustee starts, and a separate workload that carries Trustee's certificate in its Init-Data attests to it and receives a sealed resource. Run on every PR.

## Spec

`IMPLEMENTATION_SPEC.md` §9 Phase 2, §10, §11.

## Done when

- [ ] Every acceptance test except AT-16 passes in CI, including AT-24 (sealed policy enforced, unauthorized workload refused), AT-25 (Service routing) and the unlocked-Trustee side of AT-21 and AT-22.
- [ ] CI is green on a PR.
