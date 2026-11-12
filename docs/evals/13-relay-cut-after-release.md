# EV-13: Relay cut after release

**Category:** partial failure
**Runs on:** kind + swtpm; `test/e2e/evals-cluster.sh ev13`, with the attacker's `cut-attest` and `cut-close` modes
**Covers:** invariant 3 (index counted once); AT-07 at pod level; AT-18; spec §4 one operator's flow; ticket 12's note on `409` after a close

## Setup

- A 2-of-3 deployment with the pod `COLLECTING`.
- A proxy on Alice's path to the endpoint that cuts the TCP connection at a chosen point in the relay.

## Action

Alice runs `approve` with the cut at each point, and runs `status` and `approve` again after each:

1. During attestation, before the Operator Verifier answers the resource request.
2. After the Operator Verifier answers the resource request, before the helper closes the relay.

Then Bob runs `approve` with no cut.

## Expected

- Cut 1: `approve` fails with `relay ended: ...`; `status` doesn't list Alice's index; her rerun is accepted.
- Cut 2: `approve` fails. `status` lists Alice's index once in `accepted`, or not at all if the cut beat the CDH. A rerun prints `index N already accepted this boot`, or releases again and is counted once.
- After each cut, AT-18 holds on Alice's workstation: no container, listener or run directory remains.
- After each cut, the helper accepts a new relay within a few seconds, with no lasting `409`.
- Bob's Share completes the unlock with exactly two distinct indices in `accepted`.

## Results

- 2026-11-12, branch `evals-rest`, scratch VM (kind + Kata 4.2.0 + swtpm), `test/e2e/evals-cluster.sh`: **pass**. Cut 1, as the attestation answer came back: `approve` failed with `relay ended`, left nothing behind, and the helper held no Share. The retry was accepted on the first try. Cut 2, after the helper accepted: `approve` failed and left nothing behind. `status` listed Alice once, the retry said `index 1 already accepted this boot`, and Carol's Share completed the unlock.
