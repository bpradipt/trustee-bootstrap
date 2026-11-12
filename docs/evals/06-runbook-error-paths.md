# EV-06: Runbook error paths match the CLI

**Category:** operator mistake
**Runs on:** kind + swtpm; `test/e2e/evals-cluster.sh ev06`
**Covers:** *When a step fails* in [unlock-ceremony.md](../runbooks/unlock-ceremony.md), [roster-change.md](../runbooks/roster-change.md) and [trustee-upgrade.md](../runbooks/trustee-upgrade.md)

## Setup

A 2-of-3 deployment from the Unlock Ceremony runbook, part 1, with the pod `COLLECTING`.

## Action

Inject each fault, then follow the runbook from the message you see:

| Fault | How to inject it | Runbook expects |
|---|---|---|
| Wrong bundle | Operator Policy names another bundle digest | `relay ended: ... Share not accepted`; index in `rejected` |
| Wrong Init-Data | Operator Policy built from another `init.toml` | `relay ended: ...`; index not in `rejected` |
| Relay held | Attacker `hold` mode holds the relay | `open relay: ... 409` |
| Approve twice | Run the same `approve` again after success | `index N already accepted this boot` |
| Other ceremony | Share file from another Key Ceremony | `the Bootstrap Helper has key_id X, the Share file Y` |
| Disk run directory | `XDG_RUNTIME_DIR` on a disk filesystem | `start Operator Verifier: ... is not on tmpfs` |
| Swapped manifest | Another `ceremony.json` in the ConfigMap | `Init:Error`, helper exited 1, `status` never answers |
| Stale genpolicy | A changed helper arg, no new genpolicy | Event `CreateContainerRequest is blocked by policy` |
| Oversized bundle | A bundle over 1048576 bytes from stock `age` | `Init:Error`, helper exited 1 |

## Expected

For each fault:

- The CLI or the cluster shows the message or state the runbook quotes.
- The runbook's next step either fixes the fault or tells the operator to stop.
- Nothing the operator does on the way releases a Share to a CVM they didn't approve.

A message the runbook doesn't quote fails the eval, and so does a runbook step that sends the operator the wrong way.

## Results

- 2026-11-12, branch `evals-rest`, scratch VM (kind + Kata 4.2.0 + swtpm), `test/e2e/evals-cluster.sh`: **pass**. Each fault showed the text the runbook quotes, and each runbook step led to the right action. An oversized bundle can't be injected through a ConfigMap: the API server refuses one over 1 MiB (`Too long: may not be more than 1048576 bytes`), so the helper's own cap never sees it.
