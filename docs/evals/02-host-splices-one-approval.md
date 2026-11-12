# EV-02: Host splices one approval into several CVMs

**Category:** hostile host
**Runs on:** kind + swtpm, with a new `splice` mode in `test/e2e/attacker`
**Covers:** claim "no non-approved CVM receives K Shares"; invariant 1; spec §4 relay framing; ticket 03 (the host can forge the close code)

## Setup

- Two Trustee CVM pods, `cvm-1` and `cvm-2`, from the same rendered `trustee-cvm.yaml` and the same Approved Bundle. Both are approved CVMs.
- A third pod, `cvm-x`, rendered with a changed helper arg and run through genpolicy again. Its Init-Data digest differs, so it isn't approved.
- The attacker poses as the Bootstrap Helper at the endpoint Alice uses. In `splice` mode it renumbers inner connections and forwards them: 1 and 2 to `cvm-1`'s relay, 3 and 4 to `cvm-2`'s, 5 and 6 to `cvm-x`'s. Then it closes Alice's relay with `1008`.

## Action

1. Alice runs `approve` once against the attacker.
2. Alice reads the failure, follows the Unlock Ceremony runbook's *When a step fails*, and does what it tells her.
3. Bob does the same.

## Expected

- `cvm-x` receives no Share: its RCAR ends in `PolicyDeny` on every connection.
- Record how many approved CVMs accepted Alice's Share from one `approve` run, and whether the runbook led her to run `approve` a second time.

The eval fails if `cvm-x`, or any CVM outside the approved Init-Data, receives a Share.

## Notes

`approve` serves inner connections until the far end closes the relay, and nothing stops its Operator Verifier after the first release (`pkg/cli/approve.go`). The relay caps a run at 8 inner connections, two per RCAR. So a host can feed up to 4 approved CVMs from one run. Each of them runs approved code and the Approved Bundle, so the four claims hold. But K Security Operators can end up unlocking two Trustees that share one TLS key, and the threat model doesn't list that.

Decide before you run this: accept it as a residual risk, or make `approve` stop its Operator Verifier after the first release.

## Results

None yet.
