# 03: Tracer: two operators unlock through the relay, no VM

**What to build:** two Security Operators run `approve` and the Trustee CVM's helper unlocks, all in one Go test. Each `approve` opens the real outbound WebSocket relay to the helper. The helper starts its guest-loopback proxy and asks a fake CDH for the Share, and the fake CDH makes a plain HTTP request through that proxy and the relay. On the operator side, a stub resource server stands in for the Operator Verifier and serves that operator's Share payload. `status` reports progress throughout.

Build only the relay behaviour this path needs; limits and abuse handling land in ticket 12.

**Blocked by:** 02

**Status:** done

**Spec:** §4 (Helper API, one operator's flow, relay framing), §6 (`approve`, `status`); ADR 0005.

- [x] Two sequential `approve` runs unlock a 2-of-3 helper; `status` shows the accepted indices and then the unlocked state.
- [x] Inner bytes cross the relay unchanged; no listener on the operator side is bound to anything but `127.0.0.1`.
- [x] `approve` prints `accepted` or a sanitized error and never logs Share bytes.
- [x] the Go gate exits 0.

## Comments

- **the Go gate against `trustee-bootstrap` exits 0:** golangci-lint 0 issues, gremlins 39 killed, 0 lived, 0 not covered (10 timed out), jscpd no new clones. `go vet ./...` and `go test ./...` pass. The gate ran with the pinned tools under a scratch `HOME`.
- **Tests run in memory.** The sandbox denies TCP listen, so `internal/memnet` gives tests listeners and dialers built on `net.Pipe`. Production code calls `net.Listen` and `net.Dialer`. Ticket 07's CI still owes a run on real sockets.
- **WebSocket library:** `github.com/coder/websocket` v1.8.15, pinned in `go.mod`. It has no dependencies of its own, and its `Conn` lets the relay's pumps write while one goroutine reads.
- **Operator-side listener.** `approve` asks the Operator Verifier to listen on `127.0.0.1:0` and dials only the address the verifier returns. The tracer's stub verifier fails the test on any other host. Until ticket 05 lands, the shipped `approve` has no verifier and stops with an error after its status checks, so no build can release a Share without Bootstrap Attestation.
- **Outcome.** The Bootstrap Helper closes the relay with WebSocket status 1000 when it accepts the Share and 1008 when it doesn't. `approve` prints `accepted` only on 1000. A relay holder can forge either code, so the outcome informs the Security Operator and protects nothing.
- **Status after unlock.** `status` reports `COLLECTING`, `PUBLISHED` or `FAILED`; LOCKED and UNSEALING finish before any request can see them. The tracer keeps the helper's `Handler` up, so it sees `PUBLISHED`. `Helper.Serve`, which `cmd/bootstrap-helper` uses, stops listening once the last relay has closed (spec §5), so in a real CVM a `status` call after the unlock gets no answer.
- **Flags.** `approve` takes `--endpoint` and `--share-file`. `--policy`, `--kbs-binary` and the Share Commitment check need the Operator Policy (ticket 05); `--port-forward` is not built. `bootstrap-helper` takes `--manifest`, `--bundle`, `--out`, `--listen` (default `:8080`) and `--proxy-port` (default 8081). `--manifest-sha256` and `--deadline` belong to ticket 09, and the start-up check for a published tree to ticket 11.
- **Limits.** The helper answers a second concurrent relay with `409` because it holds one lock per relay; ticket 12 still owns the AT-19 test. The WebSocket read limit (9 + 64 KiB) rejects an oversized DATA frame. Idle and total timeouts, the conn_id ordering check and the 8-connection cap are ticket 12's.
