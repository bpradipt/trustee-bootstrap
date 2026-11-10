# 12: Relay limits

**What to build:** nobody can abuse the relay to reach other services or exhaust the helper. A second concurrent relay gets `409`. `conn_id` must strictly increase, with one inner connection at a time and at most 8 per relay. DATA frames stay at or under 64 KiB. The relay closes after 30 s idle or 120 s total; the limits can be lowered but not disabled. Buffers are bounded, with backpressure. The CLI dials only its own Operator Verifier port, never an address taken from a frame. Read the Comments from ticket 05 first.

**Blocked by:** 03

**Status:** ready-for-agent

**Spec:** §4 Helper API and relay framing.

- [ ] AT-19 and AT-20 pass.
- [ ] the Go gate exits 0.
