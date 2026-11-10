# 02: Tracer: unlock from Share payloads, no VM

**What to build:** the thinnest working Unlock Ceremony, run in one Go test. The Ceremony Authority runs `ceremony split` for 2-of-3. The Infrastructure Operator runs `seal` on a small config tree. A Bootstrap Helper, fed Share payloads by a fake CDH, combines two Shares, unseals the bundle and publishes the tree with its completion marker. This ticket also creates the Go module, the standalone binary and the exported command tree that `cococtl` will mount.

Keep the checks minimal: commitment, index and `key_id` validation lands in ticket 08; bundle and manifest integrity in 09; sealed-config checks in 10; crash handling in 11.

**Blocked by:** None (can start immediately)

**Status:** ready-for-agent

**Spec:** §3 items 1-5, §5, §6 (`ceremony split`, `seal`), §8; ADR 0001, 0002, 0003, 0006.

- [ ] `ceremony split` writes the Share files and the Ceremony Manifest and never writes the age identity to disk.
- [ ] `seal` produces a bundle that the stock `age` CLI can also produce, and prints its SHA-256.
- [ ] With two valid Share payloads, the helper publishes the unsealed tree and exits 0 (AT-13, in-process).
- [ ] With one, it stays locked (AT-12, in-process).
- [ ] the Go gate exits 0.
