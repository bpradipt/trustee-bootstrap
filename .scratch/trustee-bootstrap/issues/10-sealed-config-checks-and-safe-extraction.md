# 10: Sealed-config checks and safe extraction

**What to build:** nobody can unlock a Trustee that runs an unsafe config or a booby-trapped tree. One check function, called by both `seal` and the helper before publishing, refuses:
- insecure KBS token, HTTP or admin settings;
- a missing AS signer, or one whose certificate KBS doesn't trust;
- a resource policy that is missing, misplaced, empty or equal to upstream's default.

Unsealing refuses absolute paths, `..`, symlinks, hardlinks, device files and anything over the size cap. The check reads its key names from the default secure configs delivered by tickets 05 and 06.

**Blocked by:** 02, 05

**Status:** ready-for-agent

**Spec:** §3 item 4 (sealed-config checks), §5 UNSEALING, §6 `seal`; ADR 0008.

- [ ] AT-14 and AT-27 pass, including a bundle sealed with stock `age` that the helper refuses.
- [ ] Each sealed-config check fails on its own violation and passes on the default secure Trustee config.
- [ ] the Go gate exits 0.
