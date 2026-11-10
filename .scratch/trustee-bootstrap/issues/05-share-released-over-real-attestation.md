# 05: Share released over real attestation

**What to build:** a Security Operator's Share leaves their machine only after real Bootstrap Attestation. In the swtpm environment, a test pod's stock CDH asks for the Share through the guest proxy and relay from ticket 03. On the operator side the stub server is replaced by the real Operator Verifier: the pinned Trustee KBS image on `127.0.0.1`, run with the default secure Operator Verifier config. `policy build` generates that verifier's resource policy for the tpm claim profile, computing the Init-Data digest from the reviewed Init-Data TOML.

The default secure config sets `insecure_header_jwk = false`, requires the ephemeral admin key, and wires a per-run AS signer whose certificate KBS trusts. This ticket delivers it; ticket 06 derives the Trustee config from it, and ticket 10's checks read their keys from it.

**Blocked by:** 03, 04

**Status:** ready-for-agent

**Spec:** §3 item 6, §4 step 2, §6 (`policy build`, claim profiles, Operator Verifier runtime); ADR 0005.

- [ ] With matching Init-Data, the pod's CDH receives the Share payload through the relay (AT-03).
- [ ] With changed Init-Data, the Operator Verifier denies it (AT-04).
- [ ] A capture of all relay traffic contains no Share bytes (AT-06).
- [ ] The Operator Verifier runs as a digest-pinned container by default, or from `--kbs-binary`.
- [ ] Notes on RCAR connection behaviour (connections per exchange, reconnects, timing) go into ticket 12's Comments.
- [ ] the Go gate exits 0.
