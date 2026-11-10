# 16 Mount the command tree in cococtl

Status: open
Type: task
Blocked by: 13

## What

A small change to `cococtl` (fork or PR) that mounts `NewTrusteeBootstrapCmd()` as `cococtl trustee-bootstrap`, so it also works as `kubectl coco trustee-bootstrap`. Existing commands gain no new startup dependency.

## Spec

`IMPLEMENTATION_SPEC.md` §6; ADR 0001; AT-01.

## Done when

- [ ] The diff is about 5 lines plus `go.mod`.
- [ ] `cococtl`'s existing tests pass unchanged (AT-01).
