# 03: Tracer: two operators unlock through the relay, no VM

**What to build:** two Security Operators run `approve` and the Trustee CVM's helper unlocks, all in one Go test. Each `approve` opens the real outbound WebSocket relay to the helper. The helper starts its guest-loopback proxy and asks a fake CDH for the Share, and the fake CDH makes a plain HTTP request through that proxy and the relay. On the operator side, a stub resource server stands in for the Operator Verifier and serves that operator's Share payload. `status` reports progress throughout.

Build only the relay behaviour this path needs; limits and abuse handling land in ticket 12.

**Blocked by:** 02

**Status:** ready-for-agent

**Spec:** §4 (Helper API, one operator's flow, relay framing), §6 (`approve`, `status`); ADR 0005.

- [ ] Two sequential `approve` runs unlock a 2-of-3 helper; `status` shows the accepted indices and then the unlocked state.
- [ ] Inner bytes cross the relay unchanged; no listener on the operator side is bound to anything but `127.0.0.1`.
- [ ] `approve` prints `accepted` or a sanitized error and never logs Share bytes.
- [ ] the Go gate exits 0.
