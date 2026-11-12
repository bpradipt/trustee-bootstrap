# EV-13: Relay cut after release

**Category:** partial failure
**Runs on:** kind + swtpm, with a TCP proxy between `approve` and the endpoint
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

None yet.
