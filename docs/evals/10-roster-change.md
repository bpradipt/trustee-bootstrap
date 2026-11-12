# EV-10: Roster change locks out a departed operator

**Category:** roster change
**Runs on:** kind + swtpm; `test/e2e/evals-cluster.sh ev10`; part 2.3 in `go test`
**Covers:** residual risk "roster change requires a full new Key Ceremony"; invariant 3; AT-08; [roster-change.md](../runbooks/roster-change.md), which ticket 16 never walked as a whole

## Setup

- A 2-of-3 deployment of bundle A for Alice, Bob and Carol, unlocked.
- Carol leaves and keeps a copy of `carol.share` and her Operator Policy.
- The new roster is Alice, Bob and Dave, with K = 2.

## Action

1. Walk roster-change.md steps 1 to 7: a new Key Ceremony, bundle B sealed with new keys, the new pod, and two `approve` runs.
2. Carol attacks:
   1. `policy build` with her old Share and the new `ceremony.json`.
   2. `approve` with her old Share and old policy against the new pod.
   3. In `go test`: a Share payload with the new `key_id`, Carol's old index and her old Share bytes, delivered to a helper running the new manifest.
   4. With Alice's old Share, she combines K old Shares and decrypts a copy of the old A.

## Expected

- Step 1: `status` shows the new `key_id`, and the new pod unlocks.
- 2.1: `policy build` refuses the Share.
- 2.2: `approve` stops with `the Bootstrap Helper has key_id X, the Share file Y`, and nothing leaves Carol's workstation.
- 2.3: the helper rejects the payload, reports the index in `rejected` and doesn't count it.
- 2.4: A decrypts, as the runbook warns. B shares no key and no resource secret value with A, and a workload that pins A's `tls.crt` can't connect to the new Trustee.

## Results

- 2026-11-12, branch `evals-rest`, scratch VM (kind + Kata 4.2.0 + swtpm), `test/e2e/evals-cluster.sh`: **pass**. The new roster unlocked B under a new `key_id`. B has a new TLS key, certificate and secret, and a workload that pins A's certificate got nothing. `policy build` refused Carol's old Share (`the Share file has key_id …, the Operator Policy …`), and `approve` stopped it at the `key_id` check. The script doesn't decrypt the old A with old Shares: no command combines Shares outside the helper.
