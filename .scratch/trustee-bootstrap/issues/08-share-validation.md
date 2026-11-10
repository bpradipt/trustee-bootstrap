# 08: Share validation

**What to build:** the Bootstrap Helper accepts only genuine, new Shares. It rejects a payload whose `key_id` doesn't match the Ceremony Manifest, whose index isn't in the manifest or was already accepted, or whose Share doesn't match its Share Commitment. It never counts a rejected payload, and reports the bad index in status and audit. The Ceremony Manifest validator rejects repeated indices or commitments, `threshold < 2` and `threshold > len(shares)`.

**Blocked by:** 02

**Status:** ready-for-agent

**Spec:** §3 item 2, §5 COLLECTING; ADR 0003.

- [ ] AT-07 and AT-08 pass.
- [ ] Every manifest rejection has a test.
- [ ] the Go gate exits 0.
