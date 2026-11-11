# Runbooks

Each runbook names who runs it, what must be true before you start, the exact commands, what a second person checks, and what to do when a step fails. The commands match the `trustee-bootstrap` and `bootstrap-helper` releases built from this repo. Run `trustee-bootstrap <command> --help` if a flag looks wrong to you.

| Runbook | Who | Mitigates (`SECURITY_THREAT_MODEL.md`) |
|---|---|---|
| [Key Ceremony](key-ceremony.md) | Ceremony Authority, Security Operators | One operator acting as many; collusion of fewer than K operators |
| [Seal the config](seal.md) | Infrastructure Operator | The Infrastructure Operator sees the plaintext config (ADR 0008); `kbs_cert` adds a root; upstream sample configs are unsafe |
| [Unlock Ceremony](unlock-ceremony.md) | Infrastructure Operator, Security Operators | Init-Data is the single root; claim profiles cover only what was tested; TPM/swtpm gives no confidentiality; bundle rollback; host swaps the Ceremony Manifest |
| [Withdraw an approval](withdraw-approval.md) | Security Operators, Infrastructure Operator | Released Shares are irrevocable for a live boot |
| [Upgrade Trustee](trustee-upgrade.md) | Infrastructure Operator, Security Operators | Trustee replaced after unlock; availability; upstream sample configs are unsafe |
| [Change the roster](roster-change.md) | Ceremony Authority, Infrastructure Operator, Security Operators | Roster change requires a full new Key Ceremony |

## Before any runbook: verify the release

Every person who runs a command verifies the binary first. A release holds `trustee-bootstrap`, `bootstrap-helper`, one CycloneDX SBOM per binary (`*.cdx.json`) and `SHA256SUMS`. Get `SHA256SUMS` from a source the host can't change, then run:

```sh
sha256sum -c SHA256SUMS
```

Every line must say `OK`. To rebuild the release yourself, run `test/e2e/ci.sh release DIR` from a checkout of the release tag (see `docs/ci.md`).

## Audit records

`approve` writes one JSON audit record per line to stderr, next to its error messages. Keep them: add `2>>approve-audit.log` to each `approve` command. The records name these events: `verifier_started`, `relay_opened`, `relay_closed`, `verifier_stopped`, `approve_result`. A record carries the Share index, `key_id`, the endpoint, the WebSocket close code and the first line of any error. It never carries a Share, a JWE, a token, evidence or a key.

The Bootstrap Helper writes `state_changed`, `share_accepted`, `share_rejected`, `relay_opened` and `relay_closed` records to its stderr, each with `boot_id` and `key_id`. On a Trustee CVM the Kata Agent policy from genpolicy denies log reads (`ReadStreamRequest`), so `kubectl logs` shows nothing there. Use `trustee-bootstrap status` instead: its `accepted` and `rejected` lists are the helper's record you can read.
