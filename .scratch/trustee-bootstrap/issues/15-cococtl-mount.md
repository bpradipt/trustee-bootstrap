# 15: cococtl mount

**What to build:** a Security Operator runs the same commands as `cococtl trustee-bootstrap …` and `kubectl coco trustee-bootstrap …`. The `cococtl` change, delivered as a fork or PR, mounts this repo's exported command tree in about five lines. Existing commands gain no new startup dependency.

**Blocked by:** 03

**Status:** ready-for-agent

**Spec:** §6; ADR 0001.

- [ ] `cococtl`'s existing tests pass unchanged (AT-01).
- [ ] `cococtl trustee-bootstrap status` works against the ticket 03 test setup.
