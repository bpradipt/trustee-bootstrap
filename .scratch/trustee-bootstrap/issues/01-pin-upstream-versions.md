# 01: Pin upstream versions

**What to build:** a recorded set of exact upstream versions that every later ticket builds and tests against: Trustee (KBS + AS), guest-components (CDH/AA), Kata Containers, genpolicy, cloud-api-adaptor for peer-pods, and the Trustee KBS container image. Prefer recent tagged releases.

**Blocked by:** None (can start immediately)

**Status:** ready-for-agent

**Spec:** §0 requirement 7, §9 Phase 0.

- [ ] Each component has a tag and commit SHA; each image has an `@sha256` digest.
- [ ] The pins live in one document in the repo, and later tickets cite it rather than `main`.
