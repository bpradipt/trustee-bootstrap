# 16: Runbooks and supply chain

**What to build:** the people who run this have written procedures, and the release is traceable. Runbooks cover:
- the Key Ceremony;
- sealing on a controlled machine and destroying the plaintext afterwards;
- the Unlock Ceremony;
- withdrawing an approval by restarting the CVM;
- Trustee upgrades;
- roster change through a fresh Key Ceremony.

The helper and CLI emit redacted audit events. The release ships an SBOM and pinned dependencies, with no test-only flags on the production path.

**Blocked by:** 06

**Status:** done

**Spec:** §9 Phase 3; ADR 0008; threat model residual risks.

- [x] Each runbook exists and a second person can follow it without asking questions.
- [x] The release build includes an SBOM.

## Comments

**Runbooks.** `docs/runbooks/` holds one runbook per procedure plus a README that links each to the threat-model risks it mitigates. I checked every command against `--help`. On the scratch VM (kind + Kata + swtpm, release binaries from `ci.sh release`), I walked these step by step: Key Ceremony, seal (including a refused insecure tree), Unlock Ceremony (deploy, genpolicy, Init-Data review, two `policy build`s, two `approve`s, Trustee Ready), and withdraw an approval (one Share in, pod recreated, new `boot_id`, `accepted: []`). I did not walk Trustee upgrade and roster change as a whole: they chain the walked runbooks, and I ran their one new command (`kubectl create configmap ... --dry-run=client -o yaml | kubectl apply -f -`) on the VM. To repeat: `scratchpad/t16/walk/walk.sh all` on the VM after `kind-kata-swtpm.sh up`.

The walk changed the runbooks in three places:
- after the K-th Share the helper exits, so `status` gets `connection refused`, not `PUBLISHED`; the runbooks check the init container's exit code instead;
- `kubectl logs` on the Trustee CVM is empty (genpolicy sets `ReadStreamRequest := false`), so the helper's audit records are not readable there; `status` `accepted`/`rejected` is the record Security Operators can read;
- the Init-Data review greps had to target `default ExecProcessRequest` and the `request_defaults` block.

Today every claim profile is untested, so the Unlock Ceremony runbook carries a go/no-go note: no production unlock until ticket 17's real-TEE run.

**Audit events.** `internal/audit` names eight events (`state_changed`, `share_accepted`, `share_rejected`, `relay_opened`, `relay_closed`, `verifier_started`, `verifier_stopped`, `approve_result`), written as JSON lines with `log/slog`. `helper.New` takes the logger; helper records carry `boot_id` and `key_id`. `approve` writes to stderr; an error goes in as its first line only, so the KBS output a failed verifier start appends stays out. The `relay: ...` log lines are gone. `TestAuditRecordsCarryNoShare` runs a whole in-process ceremony with one rejected Share and fails on any Share, raw, hex, base64 or base64url, in either side's records. Because `approve` now writes to stderr, `share-release.sh` and `trustee-cvm.sh` keep stderr apart from the `accepted` they compare, and AT-06 also scans the audit records of both sides.

**Supply chain.** `ci.sh release DIR [VERSION]` builds both binaries with the helper image's flags, writes a CycloneDX SBOM per binary (cyclonedx-gomod v1.12.0 `bin` mode, via `go run`, verified by the Go checksum database) and `SHA256SUMS`. The `go` job runs it and uploads the `release` artifact (upload-artifact pinned by SHA). I ran it on the VM: the CLI's SBOM lists the nine modules it links (go.mod less the Windows-only mousetrap). `ci.sh go` adds `go mod tidy -diff` and `go mod verify`. `test/supplychain` (in `go test ./...`) fails on an image without a digest, an action without a commit SHA, a release binary that links `testing`, `httptest`, `memnet`, `trusteetest` or `test/...`, or a non-test Go file under `test/`. The check passes today: neither binary links any test-only package.

Not covered: the SBOMs carry no licence data. cyclonedx-gomod reads the licence per module, which would label the whole vault module BUSL although we link only its MPL-2.0 `shamir` package. The CI release job builds with the Go version in go.mod (1.25.3), while the helper image builds with 1.26.4.

**Gate.** The worktree guard refused the `HOME=` override, so I ran the gate's tools directly with its config: golangci-lint 0 issues, gremlins 5 killed / 0 lived / 0 not covered, jscpd 0 clones. The orchestrator must run the real the Go gate before merging. `go vet ./...` and `go test ./...` pass; shellcheck and actionlint are clean.

**e2e.** `ci.sh e2e` on the VM: profiles and `share-release.sh` passed (AT-06 now reports "the audit log (18 records) holds no Share"). `trustee-cvm.sh` failed at AT-26 with the known Kata agent create-container timeout (13-notes); everything before it passed. A rerun of `kind-kata-swtpm.sh up` plus `trustee-cvm.sh` passed in full, AT-26 included. Logs: `~/t16/e2e.log`, `~/t16/cvm2.log`.
