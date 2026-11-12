# 23: Build the e2e guest artifacts once and pull them from ghcr.io

**What to build:** a workflow builds the swtpm e2e guest artifacts into one OCI image on ghcr.io:

- the Kata guest kernel with TPM drivers;
- the Attestation Agent with the TPM attester;
- the coco-extension image that carries that AA;
- the shim, rootfs image and config that `up` takes from the kata-static tarball.

The e2e job pulls that image. Only a change to a pinned version, or to the build itself, builds a new one.

**Why:**

- A cold e2e run spends about 20 minutes on the kernel and the AA.
- The e2e job's `actions/cache` key hashes `kind-kata-swtpm.sh` and `trustee-cvm.sh`, so most PRs that touch the e2e scripts build from scratch.
- GitHub drops a cache after 7 days without use, and a PR branch reads only its own caches and `main`'s.
- The scratch VM and each developer build the same files again.

**Design**, agreed 2026-11-12:

- **`versions.yaml`** at the repo root holds the pins that the e2e scripts use, one flat `key: value` per line, so a shell function reads it with `awk` and nothing needs `yq`. `docs/upstream-pins.md` keeps the source and the reason for each. `test/supplychain` fails if a value in `versions.yaml` is missing from the doc, or if `pkg/verifier`'s KBS image differs from `versions.yaml`'s.
- **`test/e2e/guest-build.sh`** holds the build steps, moved from `kind-kata-swtpm.sh`.
- **The image** is `ghcr.io/confidential-devhub/trustee-bootstrap-e2e-guest`, with the files under `/e2e-guest`. Its base is the pinned busybox image, so `cp` can copy the files out. Its tag is the sha256 of `versions.yaml`, `guest-build.sh` and `kernel-tpm.conf`.
- **`kind-kata-swtpm.sh up`** pulls that tag, and builds as before if the pull fails. A stamp file in `$E2E_CACHE/out` records the tag, so `up` replaces files built for other pins.
- **`.github/workflows/e2e-guest.yml`** runs on pushes to `main` that change those files, and on `workflow_dispatch`. It skips a tag the registry already has. Only this job gets `packages: write`.
- **`test/supplychain`** exempts this one repository from the digest rule. Its tag hashes its inputs, and only our workflow pushes it.
- **`ci.yml`** drops `actions/cache`.

A PR that changes the tag finds no image and builds once. After the merge, the workflow publishes the image, and later runs pull it.

**Blocked by:** none

**Status:** in-progress

**Spec:** §0 requirement 7 (pin every upstream version); `docs/ci.md`; `docs/upstream-pins.md`.

- [x] With the image in the registry, `up` pulls it and builds nothing, and the swtpm e2e tests pass on the pulled files.
- [x] With no image for the tag, `up` builds the files as before, and `kind-kata-swtpm.sh publish` packs and pushes them.
- [x] A changed pin changes the tag, and `up` replaces a local cache built for the old one.
- [x] `test/supplychain` exempts only the e2e guest repository, and fails if `versions.yaml` and `docs/upstream-pins.md` disagree.
- [ ] After the merge, the workflow publishes the image, and the package is public.
- [x] `test/e2e/ci.sh go`, `test/e2e/ci.sh lint <base>` and `test/e2e/golden-path.sh` exit 0.

## Comments

- **Verified** on the scratch VM (kind + Kata 4.2.0 + swtpm, rootful podman), 2026-11-12. A registry on `localhost:5001` stood in for ghcr.io, through `E2E_GUEST_IMAGE`:
  - **Pins.** The 16 values that `pin` reads from `versions.yaml` equal the literals they replaced in `kind-kata-swtpm.sh` and `trustee-cvm.sh`. A missing key stops the script. `clone_at` and the four build functions moved to `guest-build.sh` unchanged, byte for byte.
  - **Publish.** `kind-kata-swtpm.sh publish` packed the cached files and pushed them. A second `publish` found the tag and skipped.
  - **Pull.** With the stamp set to another tag, `guest` removed the cached files and pulled the image. The pulled files are byte-identical to the built ones.
  - **Tag.** Editing `guest-build.sh` changed the tag, from `5c3051b8…` to `745caa70…`.
  - **e2e.** On a fresh cluster (`down`, then `up` from the pulled files), `test/e2e/ci.sh e2e` passed: AT-28 profiles, `share-release.sh` and `trustee-cvm.sh`. Then `up` and `golden-path.sh` passed.
  - **supplychain.** It goes red on each of these: a pin missing from `docs/upstream-pins.md`, a quoted value, a KBS image that differs from `verifier.Image`, and a lookalike `…-e2e-guestx` reference.
  - `test/e2e/ci.sh go`, `test/e2e/ci.sh lint origin/main` and shellcheck exit 0.
- **Not run: a cold build.** The VM had 2.5 GB free, too little for the kernel and the AA. The build code moved unchanged. ghcr.io has no image yet, so this PR's e2e job takes the build path and covers box 2.
- **Cold build in CI**, PR run 43253675354, 2026-11-12. ghcr.io had no image for the tag, so `up` built everything itself: the kernel from 15:59 to 16:10, the AA until 16:18, then the extension and the kata-static files. `share-release.sh` passed on those files. In `trustee-cvm.sh`, so did AT-13's TPM-attested unlock and the policy checks.
- **A race in that run.** AT-21 then failed with `connection refused` to Trustee's ClusterIP, 0.83 s after the pod turned Ready. kube-proxy routes a Service a moment after its pod turns Ready, and this runner reached the check sooner than the VM ever had. `check_host_attacks` now waits until the node can open a TCP connection to the Service.
- **First publish failed**, `main` run 43271785832, 2026-11-12. The build passed, but the push to `ghcr.io/confidential-devhub/...` was refused: `denied: permission_denied: The requested installation does not exist`. The repository runs as `bpradipt/trustee-bootstrap`, and a workflow token pushes only under its own owner. Both workflows now set `E2E_GUEST_IMAGE` to `ghcr.io/<repository owner>/trustee-bootstrap-e2e-guest`. On the VM, a publish to a local registry under a mixed-case owner pushed the lowercased name, with `GITHUB_REPOSITORY` in the source label. `golden-path.sh` passed.
