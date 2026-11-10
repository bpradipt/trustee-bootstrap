# 12: Relay limits

**What to build:** nobody can abuse the relay to reach other services or exhaust the helper. A second concurrent relay gets `409`. `conn_id` must strictly increase, with one inner connection at a time and at most 8 per relay. DATA frames stay at or under 64 KiB. The relay closes after 30 s idle or 120 s total; the limits can be lowered but not disabled. Buffers are bounded, with backpressure. The CLI dials only its own Operator Verifier port, never an address taken from a frame. Read the Comments from ticket 05 first.

**Blocked by:** 03

**Status:** ready-for-agent

**Spec:** §4 Helper API and relay framing.

- [ ] AT-19 and AT-20 pass.
- [ ] the Go gate exits 0.

## Comments

### RCAR through the relay, observed in ticket 05

These come from `tcpdump` on the scratch VM during `test/e2e/share-release.sh` (stock CDH and AA from guest-components v0.22.0, TPM attester, KBS v0.22.0). The loopback leg between the CLI and the Operator Verifier shows each inner connection the relay carried.

- **Two inner connections per successful exchange.** Connection 1 carries `POST /kbs/v0/auth` and then `POST /kbs/v0/attest` (keep-alive). Connection 2 carries `GET /kbs/v0/resource/trustee-bootstrap/share/current`.
- **The connections overlap.** The guest opens connection 2 about 0.2 ms before connection 1 closes (SYN of 2 at `.650520`, FIN of 1 at `.650754`; the same order in both approvals). The guest sends OPEN for the next `conn_id` before CLOSE for the previous one. If the relay rejects an OPEN while a connection is still open, you break every unlock. Allow the overlap, or close the older connection when a newer `conn_id` opens.
- **Timing.** Auth to resource response takes 90 to 100 ms. The attest call takes about 30 ms of that. `approve` takes about 2 s end to end, mostly the KBS start.
- **Retries on denial.** With changed Init-Data, KBS answered `PolicyDeny` and the CDH ran the whole RCAR again: 4 auth/attest rounds and at least 3 resource GETs within about 300 ms. Each round uses two connections, so a denied exchange reaches about 8 inner connections, the per-relay cap. A cap of 8 may cut off the last retry of a denial, which changes nothing. A success uses 2 of the 8.
- **No reconnects** on the success path, and the CDH never reused a connection across the auth and resource steps.
