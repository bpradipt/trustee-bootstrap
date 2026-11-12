# 01: Pin upstream versions

**What to build:** a recorded set of exact upstream versions that every later ticket builds and tests against: Trustee (KBS + AS), guest-components (CDH/AA), Kata Containers, genpolicy, cloud-api-adaptor for peer-pods, and the Trustee KBS container image. Prefer recent tagged releases.

**Blocked by:** None (can start immediately)

**Status:** done

**Spec:** §0 requirement 7, §9 Phase 0.

- [ ] Each component has a tag and commit SHA; each image has an `@sha256` digest.
- [x] The pins live in one document in the repo, and later tickets cite it rather than `main`.

## Comments

The pins live in `docs/upstream-pins.md`. They follow the CoCo v0.23.0 release set: Kata 4.2.0, Trustee and guest-components v0.22.0, CAA v0.23.0. The spec pointer and spec §12 now link to that file.

Every component has a tag and commit, and the KBS, kata-deploy and coco-extension images have digests. The first box stays open for one image: CAA v0.23.0 ships on quay.io only, and this sandbox could not reach quay.io. The doc gives the `skopeo` command that resolves it. No ticket before peer-pods needs CAA.

The sandbox could not reach ghcr.io either, so the other digests come from each package's GitHub Packages page. Re-check them with `skopeo inspect` when you have registry access.
