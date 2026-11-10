# 09: Bundle and manifest integrity

**What to build:** the host can't make the Trustee CVM unseal anything but the Approved Bundle. The helper refuses to start when `--manifest-sha256` is missing, empty or doesn't match. It reads the manifest and the bundle into memory once, with a size cap, and hashes and decrypts only those bytes. It accepts a Share only if its `bundle_sha256` matches the in-memory bundle. A released Share stays valid for the rest of the boot; `--deadline` is optional cleanup.

**Blocked by:** 02

**Status:** ready-for-agent

**Spec:** §5 LOCKED and COLLECTING; ADR 0004, 0007.

- [ ] AT-09, AT-10, AT-11 and AT-23 pass.
- [ ] Swapping either file on disk after LOCKED changes nothing the helper does.
- [ ] the Go gate exits 0.
