# 09 Relay

Status: open
Type: task
Blocked by: 07

## What

`pkg/relay/`: the byte-transparent tunnel.

- Framing: 9-byte header (`type` u8: OPEN=1, DATA=2, CLOSE=3; `conn_id` u64 big-endian), DATA ≤ 64 KiB.
- Helper side: WebSocket server for `GET /bootstrap/v1/relay` (one relay at a time, second gets `409`), plus the guest-loopback proxy that emits OPEN per accepted connection.
- CLI side: WebSocket client that dials only its configured local Operator Verifier port, never an address from a frame.
- Limits: strictly increasing `conn_id`, one inner connection at a time, at most 8 per relay, 30 s idle, 120 s total (lowerable, not disableable), bounded buffers with backpressure, full cleanup on disconnect. Inner bytes are never parsed or logged.

Read ticket 03's Comments first.

## Spec

`IMPLEMENTATION_SPEC.md` §4 Helper API and Relay framing; ADR 0005.

## Done when

- [ ] An in-process test pipes an HTTP exchange through proxy, relay and client unchanged.
- [ ] AT-19 and AT-20 pass as unit tests.
- [ ] the Go gate exits 0.
