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
- `cvm-1` and `cvm-2` both accept Alice's Share from her one `approve` run. This is the documented residual risk *an approval covers a configuration, not one VM*.
- One `approve` run feeds at most 4 CVMs.
- After the forged `1008`, the runbook leads Alice to stop and check with the other Security Operators. It doesn't lead her to run `approve` again for that boot.

The eval fails if `cvm-x`, or any CVM outside the approved Init-Data, receives a Share. It also fails if one run feeds more than 4 CVMs, or if the runbook sends Alice back to `approve`.

## Notes

`approve` serves inner connections until the far end closes the relay, and nothing stops its Operator Verifier after the first release (`pkg/cli/approve.go`). The relay caps a run at 8 inner connections (`pkg/relay/relay.go`), and each RCAR uses two.

Decided on 2026-11-12: accept and document, in `SECURITY_THREAT_MODEL.md` and the Unlock Ceremony runbook. A cap of 2 inner connections per relay would limit each run to one release and change the 4 above to 1. It stays an option. It depends on CDH using exactly two connections per exchange, as guest-components v0.22.0 does (ticket 12).

## Results

None yet.
