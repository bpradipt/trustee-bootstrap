# 11: Crash recovery

**What to build:** a helper crash never leaves a half-published tree or forces an unneeded ceremony. The helper writes the completion marker into the staging tree, syncs it, then renames staging into place, so the rename is the single commit point. On start, it exits 0 if the marked tree exists, and otherwise wipes leftover staging and begins a fresh `boot_id` with no Shares.

**Blocked by:** 02

**Status:** done

**Spec:** §5 (on start, PUBLISHED, restarts); ADR 0002.

- [x] AT-15 and AT-26 pass, with crashes injected just before and just after the rename.
- [x] the Go gate exits 0.

## Comments

- `helper.Recover(out)` is the start-up step. It returns true when `out` holds the completion marker, and
  `cmd/bootstrap-helper` then exits 0 before it reads the mounts or listens. Otherwise it removes
  `out + ".staging"` and the helper enters LOCKED with a new `boot_id` and no Shares. An Lstat error other
  than "not found" (for example, `--out` is a file) fails the start. An empty `--out` is now fatal, so the
  wipe can't hit `./.staging`.
- Publication: Unseal, sealed-config checks, write the marker, fsync every file and directory in staging,
  rename staging to `out`, fsync the parent. A failed rename also removes staging. On the guest tmpfs the
  fsyncs cost nothing and do nothing; they matter only if `--out` ever sits on a disk.
- Crash seam: a package var `rename = os.Rename` in pkg/helper, swapped by `SetRename` in `export_test.go`.
  The hook panics with a sentinel and the test recovers it, so nothing after the hook runs, as in a dead
  process. `TestCrashBeforeRenameNeedsNewCeremony` (AT-15, AT-26 before) and
  `TestCrashAfterRenameKeepsPublishedTree` (AT-26 after) restart through `Recover` and `New`.
  `TestRunExitsZeroWhenAlreadyPublished` and `TestRunWipesLeftoverStaging` cover the same paths through `run`.
- AT-26 Trustee restart, pod level: `trustee-cvm.sh check_trustee_restart` stops the KBS container with
  `crictl stop` on the kind node. Kubelet restarts it in the same sandbox, the helper's restartCount stays the
  same, and a new `workload-again` probe gets the sealed resource with no ceremony. genpolicy's rules allow
  `SignalProcessRequest` by default.
- Ran on the scratch VM: worktree synced to `~/t11/src`, then
  `E2E_CACHE=~/t07/cache/e2e PATH=$HOME/sdk/go/bin:$PATH ./test/e2e/ci.sh e2e`. share-release and
  trustee-cvm both printed PASS, including the AT-26 line. The cluster was deleted at the end.
- Gate: the Go gate against `trustee-bootstrap` exit 0 (golangci 0 issues, gremlins 9/9 killed, no new clones).
  The first run had two LIVED mutants on fsync error checks, which no test can observe. `syncPath` now
  returns `errors.Join(err, f.Sync(), f.Close())` with no branch; a nil `*os.File` returns `os.ErrInvalid`.
- Not covered: a host crash between the rename and the parent fsync on a real disk. The rename can then be
  lost, and the restart wipes staging and asks for a new ceremony, which is the safe side.
