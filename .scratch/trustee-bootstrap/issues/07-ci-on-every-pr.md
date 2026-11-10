# 07: CI on every PR

**What to build:** every pull request runs the in-process ceremony from ticket 03 and the swtpm end-to-end ceremony from ticket 06, and blocks merge on failure. Later hardening tickets add their acceptance tests to this pipeline.

**Blocked by:** 06

**Status:** ready-for-agent

**Spec:** §9 Phase 2, §11.

- [ ] A PR runs the Go gate, the Go tests and the swtpm end-to-end test.
- [ ] A deliberately broken PR fails CI.
