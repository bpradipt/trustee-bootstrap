# 12: Relay limits

**What to build:** nobody can abuse the relay to reach other services or exhaust the helper. A second concurrent relay gets `409`. `conn_id` must strictly increase, with one inner connection at a time and at most 8 per relay. DATA frames stay at or under 64 KiB. The relay closes after 30 s idle or 120 s total; the limits can be lowered but not disabled. Buffers are bounded, with backpressure. The CLI dials only its own Operator Verifier port, never an address taken from a frame. Read the Comments from ticket 05 first.

**Blocked by:** 03

**Status:** done

**Spec:** §4 Helper API and relay framing.

- [x] AT-19 and AT-20 pass.
- [x] the Go gate exits 0.

## Comments

### RCAR through the relay, observed in ticket 05

These come from `tcpdump` on the scratch VM during `test/e2e/share-release.sh` (stock CDH and AA from guest-components v0.22.0, TPM attester, KBS v0.22.0). The loopback leg between the CLI and the Operator Verifier shows each inner connection the relay carried.

- **Two inner connections per successful exchange.** Connection 1 carries `POST /kbs/v0/auth` and then `POST /kbs/v0/attest` (keep-alive). Connection 2 carries `GET /kbs/v0/resource/trustee-bootstrap/share/current`.
- **The connections overlap.** The guest opens connection 2 about 0.2 ms before connection 1 closes (SYN of 2 at `.650520`, FIN of 1 at `.650754`; the same order in both approvals). The guest sends OPEN for the next `conn_id` before CLOSE for the previous one. If the relay rejects an OPEN while a connection is still open, you break every unlock. Allow the overlap, or close the older connection when a newer `conn_id` opens.
- **Timing.** Auth to resource response takes 90 to 100 ms. The attest call takes about 30 ms of that. `approve` takes about 2 s end to end, mostly the KBS start.
- **Retries on denial.** With changed Init-Data, KBS answered `PolicyDeny` and the CDH ran the whole RCAR again: 4 auth/attest rounds and at least 3 resource GETs within about 300 ms. Each round uses two connections, so a denied exchange reaches about 8 inner connections, the per-relay cap. A cap of 8 may cut off the last retry of a denial, which changes nothing. A success uses 2 of the 8.
- **No reconnects** on the success path, and the CDH never reused a connection across the auth and resource steps.

### Done in ticket 12

- **Overlap: a newer OPEN closes the older connection.** Both sides do it, and the side that closes it sends `CLOSE`. The guest now sends `CLOSE 1` before `OPEN 2`. I chose this over a grace window because it keeps spec §4's "one inner connection at a time" literal, and it needs no extra timer. The CDH opens connection 2 only after it reads the attest response, so connection 1 has no bytes left to carry. Against the threat model row "Relay used to reach other local services", a relay holder can keep at most one connection to the Operator Verifier open, and it can't reach any other address. Spec §4 now says this.
- **Other limits.** `conn_id` must increase, and the Operator side ends the relay on a repeat, a zero or a smaller id before it dials. A relay opens at most 8 inner connections. The guest's ninth loopback connection ends the relay, and the Operator side refuses a ninth `OPEN` without dialling. DATA over 64 KiB fails the WebSocket read limit on both sides. Idle (no frame in either direction) and total timers on both sides close the relay with `1008` and the reasons `relay idle` or `relay open too long`. A blocking write to an inner connection is the backpressure. When a limit ends the relay, the code closes the inner connection first, so a write stuck on it can't hold the relay open.
- **Configurable, never disabled.** `relay.Limits` and `Limits.Check` refuse a zero, negative or above-default value. `Guest` and `Operator` check too. The `--relay-idle-timeout` and `--relay-total-timeout` flags on `bootstrap-helper` and `approve` check at start, before anything listens or starts.
- **AT-19** `pkg/helper` `TestSecondConcurrentRelayGetsConflict`. **AT-20** `pkg/relay/limits_test.go` (Operator framing violations and the cap, the 64 KiB and 8-connection boundaries, newer-OPEN-closes-older on both sides, the guest's ninth connection, idle and total limits on each side, traffic keeping a relay open, `Limits.Check`), plus flag tests in `pkg/cli` and `cmd/bootstrap-helper`.
- **Race fixed.** `accept` used to share one `id` variable with each pump goroutine, so a pump could send `CLOSE` with a later `conn_id`. `go test -race` on the VM found it. Each loop iteration now has its own `id`.
- **Gate:** the Go gate against `trustee-bootstrap` PASS (golangci 0 issues, gremlins 21 killed / 0 lived / 0 not covered, jscpd no new clones). `go vet` and `go test ./...` pass locally. `go test -race -count=3 ./...` passes on the VM.
- **VM e2e with the limits on:** `E2E_CACHE=~/t07/cache/e2e test/e2e/ci.sh e2e` from `~/t12/src` (rsync of this worktree) exited 0. share-release passed (AT-03 both Shares accepted, AT-04 denial released nothing, AT-06), and trustee-cvm passed (AT-13 real unlock, AT-25, AT-17, AT-24, AT-26, AT-11). Log: `~/t12/e2e.log` on the VM.
- **Not changed:** a second relay opened right after the previous one closes can still get `409` (09-notes). That is the helper releasing its lock after the close handshake. A real `approve` starts the KBS first (~2 s), so the e2e never hits it.
- Review fixes: `relay.Limits` has unexported fields now. `DefaultLimits` and `NewLimits` are the only ways
  to set them, so the check runs once, at flag parsing; `Guest` and `Operator` no longer re-check. The zero
  `Limits` ends a relay at once, so it can't disable the limits. `relay.LimitFlags` defines both flags once
  for the helper and for `approve` (cobra adds them through `AddGoFlagSet`). The timing tests run under
  `testing/synctest` (Go 1.25), so they no longer sleep.
