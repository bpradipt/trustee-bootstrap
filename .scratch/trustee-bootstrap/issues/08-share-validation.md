# 08: Share validation

**What to build:** the Bootstrap Helper accepts only genuine, new Shares. It rejects a payload whose `key_id` doesn't match the Ceremony Manifest, whose index isn't in the manifest or was already accepted, or whose Share doesn't match its Share Commitment. It never counts a rejected payload, and reports the bad index in status and audit. The Ceremony Manifest validator rejects repeated indices or commitments, `threshold < 2` and `threshold > len(shares)`.

**Blocked by:** 02

**Status:** done

**Spec:** §3 item 2, §5 COLLECTING; ADR 0003.

- [x] AT-07 and AT-08 pass.
- [x] Every manifest rejection has a test.
- [x] the Go gate exits 0.

## Comments

- `ceremony.Manifest.Validate` holds the four manifest rejections; `helper.New` calls it. `Manifest.CommitmentFor`
  replaces the copy that lived in `pkg/policy`.
- `Helper.CollectShare` runs the COLLECTING checks (`key_id`, index in the manifest, index not yet accepted,
  Share Commitment). A rejected payload is not counted. Its index goes into the new `rejected` status field
  (each index once), and the returned error names it. `serveRelay` logs that error, so the log line is the
  audit record until the Phase 3 audit events exist. Spec §4 now lists `rejected` in the status body.
- `bundle_sha256` is still unchecked; ticket 09 adds it. `TestServeFailsWhenUnsealFails` now pairs genuine
  Shares with a bundle sealed to another recipient. Ticket 09 rejects that case earlier, so it must update this test.
- Tests: `TestManifestValidate`, `TestSameIndexTwiceCountedOnce` (AT-07), `TestBadShareRejectedAndReported`
  (AT-08, unknown index, other `key_id`), `TestRejectedIndexReportedOnce`, `TestNewRejectsInvalidManifest`.
- the Go gate against `trustee-bootstrap`: PASS, exit 0 (gremlins 10 killed, 0 lived, 0 not covered).
- `ci.sh e2e` passed on the scratch VM (share-release and trustee-cvm both PASS), since the status body gained a
  field. To repeat: `vmsync <worktree> t08/src`, then on the VM
  `cd ~/t08/src && PATH=$HOME/sdk/go/bin:$PATH E2E_CACHE=$HOME/t07/cache/e2e test/e2e/ci.sh e2e`.
