# 01 Pin upstream versions

Status: open
Type: spike
Blocked by: none

## What

Choose and record the exact upstream versions everything else builds on: Trustee (KBS + AS), guest-components (CDH/AA), Kata Containers, genpolicy, cloud-api-adaptor (for peer-pods), and the Trustee KBS container image digest. Prefer recent tagged releases; record the commit SHA for each.

## Spec

`IMPLEMENTATION_SPEC.md` §9 Phase 0, first item; §0 requirement 7.

## Done when

- [ ] `docs/upstream-pins.md` lists each component with tag, commit SHA and, for images, `@sha256` digest.
- [ ] Every later ticket cites these pins rather than `main`.
