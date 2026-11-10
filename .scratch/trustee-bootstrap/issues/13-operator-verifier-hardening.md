# 13: Operator Verifier hardening

**What to build:** neither verifier releases anything to a forged token or an unauthenticated admin call, and `approve` leaves nothing behind. The Operator Verifier listens only on `127.0.0.1`. It refuses to start with insecure token or admin settings. Its tmpfs directory, container and listener disappear on success, failure and signals. The unlocked Trustee resists the same attacks.

**Blocked by:** 05

**Status:** ready-for-agent

**Spec:** §4 step 2, §6; threat model rows for forged tokens and admin calls.

- [ ] AT-02 and AT-18 pass.
- [ ] A malicious relay that replays old evidence or substitutes its own `tee-pubkey` gets no release (AT-05).
- [ ] AT-21 and AT-22 pass against both the Operator Verifier and the unlocked Trustee (the latter once ticket 06 is done).
- [ ] the Go gate exits 0.
