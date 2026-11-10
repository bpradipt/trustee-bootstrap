# 13 approve and status commands

Status: open
Type: task
Blocked by: 09, 11, 12

## What

Wire the operator flow in `pkg/cli`: `approve --endpoint URL --policy DIR --share-file FILE [--kbs-binary PATH] [--port-forward]` and `status --endpoint URL`.

`approve` checks the Share against its commitment, starts the Operator Verifier, calls `status` (key_id, own index not yet accepted), opens the relay, waits for the outcome, tears down, and prints `accepted` or a sanitized error. Accept `http://` and `https://` endpoints. Never log Shares, JWEs, tokens or evidence; never reuse `~/.kube/coco-config.toml`.

## Spec

`IMPLEMENTATION_SPEC.md` §4 "One operator's flow", §6.

## Done when

- [ ] An in-process test runs `approve` against the ticket 10 helper with a fake CDH and a real relay.
- [ ] the Go gate exits 0.
