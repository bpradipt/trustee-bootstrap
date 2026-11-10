# 11: Crash recovery

**What to build:** a helper crash never leaves a half-published tree or forces an unneeded ceremony. The helper writes the completion marker into the staging tree, syncs it, then renames staging into place, so the rename is the single commit point. On start, it exits 0 if the marked tree exists, and otherwise wipes leftover staging and begins a fresh `boot_id` with no Shares.

**Blocked by:** 02

**Status:** ready-for-agent

**Spec:** §5 (on start, PUBLISHED, restarts); ADR 0002.

- [ ] AT-15 and AT-26 pass, with crashes injected just before and just after the rename.
- [ ] the Go gate exits 0.
