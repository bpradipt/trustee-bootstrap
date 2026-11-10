# Upstream pins

Every ticket builds and tests against these versions. Cite this file, not `main` or `latest`. Spec §0 requirement 7 and §9 Phase 0.

Checked on 2026-11-10 against the sources listed under each table.

## The set

We pin the Confidential Containers **v0.23.0** release set. Its release notes name Kata Containers 4.2.0 with Trustee and guest-components v0.22.0, and CoCo tested that combination. CAA v0.23.0 builds its pod VM from the same three.

Kata 4.3.0 and 4.3.1 are newer, and they pin the same Trustee and guest-components commits. To move to 4.3.x, repeat these checks first.

## Source pins

| Component | Tag | Commit |
|-----------|-----|--------|
| Trustee (KBS + AS) | `v0.22.0` | `512fed65642015b849f38fb13bfdec7806639987` |
| guest-components (CDH, AA) | `v0.22.0` | `eae0bf63a3a9db7721f86e0a2b0b9941a7fcba3a` |
| Kata Containers | `4.2.0` | `c7351e797efff8bfc6bd73da0eb1909be12e2cfe` |
| genpolicy | Kata `4.2.0` | `c7351e797efff8bfc6bd73da0eb1909be12e2cfe` |
| cloud-api-adaptor (peer-pods) | `v0.23.0` | `e3e0f00480b41c08e3e4dbc6b64aba7722fb65f9` |
| CoCo release (umbrella) | `v0.23.0` | `f3357873187b547a660cae8d2c347dd5e68749f3` |

These tags are lightweight, so each one points straight at the commit (`git ls-remote --tags`).

Cross-checks:

- Kata 4.2.0 `versions.yaml` sets `externals.coco-trustee.version` and `externals.coco-guest-components.version` to the Trustee and guest-components commits above.
- CAA v0.23.0 `src/cloud-api-adaptor/versions.yaml` names the same two commits, plus `kata-containers` at `c7351e79…` (4.2.0).
- The CoCo v0.23.0 release notes say: Kata 4.2.0, Trustee and guest-components v0.22.0, KBS protocol v0.4.0.

Sources:

- https://github.com/confidential-containers/trustee/releases/tag/v0.22.0
- https://github.com/confidential-containers/guest-components/releases/tag/v0.22.0
- https://github.com/kata-containers/kata-containers/releases/tag/4.2.0
- https://github.com/kata-containers/kata-containers/blob/4.2.0/versions.yaml
- https://github.com/confidential-containers/cloud-api-adaptor/releases/tag/v0.23.0
- https://github.com/confidential-containers/cloud-api-adaptor/blob/v0.23.0/src/cloud-api-adaptor/versions.yaml
- https://github.com/confidential-containers/confidential-containers/blob/v0.23.0/releases/v0.23.0.md

## Container images

Pull by digest. The tag is there so a reader can see what the digest is.

| Image | Tag | Index digest | linux/amd64 digest |
|-------|-----|--------------|--------------------|
| `ghcr.io/confidential-containers/key-broker-service` | `built-in-as-v0.22.0` | `sha256:c1960cb4df0b1bdc0e4309f97dc65b0a1a777a92dabb2211acb45542f906c625` | `sha256:ec207ed73a8be06b0e75c74723b8eed30fa10c25f38be54ea20c9b8e84a4420b` |
| `ghcr.io/kata-containers/kata-deploy` | `4.2.0` | `sha256:14099d6d98e6b4c3a112da59a05180724be15ad96387dcd7674c1225525a10de` | `sha256:7d43d21c9f1beba2b7b4cd8be0da40680b5fca34039f1e6ae19cceb5579f61d2` |
| `ghcr.io/confidential-containers/guest-components/coco-extension` | `eae0bf63a3a9db7721f86e0a2b0b9941a7fcba3a-ubuntu26.04` | `sha256:e10ac1d0b915100f8212bb0be4f28669ac80588b3ba922c4580a36d23c5fb47a` | `sha256:af3515cc8b2254a3c4cf39bdc9909ae03142609faef9c3375d261a12651bff22` |
| `quay.io/confidential-containers/cloud-api-adaptor` | `9b608e60b032222488adec09e61dbf40f3c71e8f` | **unresolved**, see below | **unresolved** |

Other platforms in the indexes:

- KBS `built-in-as-v0.22.0`: linux/s390x `sha256:397965cb67ed3e69c114e2ead645429efdf1a6d2b7ece18acaf9591ffe4a3c27`. The release has no arm64 image.
- kata-deploy `4.2.0`: arm64 `sha256:29b62e452c66bf2e216c1b5524af981b29a6e3aadb1fd88418f162f623cac5f4`, ppc64le `sha256:54945db461be99286e4398cd8154cf9301be4b223936df77ecc1fcd726b83a1f`, s390x `sha256:cf37ef95c9edb5dcda920bebffbb77f55f8b397aec661a00e9d07985ca308acd`.
- coco-extension: arm64 `sha256:2d6bf66bcd291eaf2726f6d3bfc785f01c218ffa6d95e352bb9cfbb1055c0ee7`, s390x `sha256:479d74e0cae86b327b7ce7fd2d5ea0cf0ad17dfb1fe5c6fa2ca9369ede34e44a`.

The kata-deploy Helm chart defaults to `quay.io/kata-containers/kata-deploy`. Kata also publishes the release to ghcr.io, and the digest above belongs to the ghcr.io repository. Set `image.reference=ghcr.io/kata-containers/kata-deploy` when you install the chart.

The CAA v0.23.0 peerpods chart sets `image.name: quay.io/confidential-containers/cloud-api-adaptor` and `image.tag: 9b608e60b032222488adec09e61dbf40f3c71e8f`. The libvirt provider uses `dev-9b608e60…`. CAA pushed this release to quay.io only; its ghcr.io package holds CI images from that period. The sandbox used for this check could not reach quay.io, so the digest is open. Resolve it before any peer-pods ticket uses CAA:

```sh
skopeo inspect --raw docker://quay.io/confidential-containers/cloud-api-adaptor:9b608e60b032222488adec09e61dbf40f3c71e8f | sha256sum
```

Sources. The registries were unreachable from the sandbox, so the digests come from each package's GitHub Packages page, which ghcr.io serves:

- https://github.com/confidential-containers/trustee/pkgs/container/key-broker-service/1264642240?tag=built-in-as-v0.22.0
- https://github.com/kata-containers/kata-containers/pkgs/container/kata-deploy/1251417741?tag=4.2.0
- https://github.com/confidential-containers/guest-components/pkgs/container/guest-components%2Fcoco-extension/1235452975?tag=eae0bf63a3a9db7721f86e0a2b0b9941a7fcba3a-ubuntu26.04
- https://github.com/confidential-containers/cloud-api-adaptor/blob/v0.23.0/src/cloud-api-adaptor/install/charts/peerpods/values.yaml

Re-check each digest with `skopeo inspect` once you have registry access, and fix this file if one differs.

## Release files

| File | sha256 |
|------|--------|
| `kata-tools-static-4.2.0-amd64.tar.zst` (holds `genpolicy`, `rules.rego`, `genpolicy-settings.json`) | `a4f8e1b6ee500b6e94d3925249e741c75bb4a89bf275b5d5066d6275c68e29ef` |
| `opt/kata/bin/genpolicy` inside that tarball | `48b12625bd47bb9279b444ed0d52233bf30ffab86e7af69f0ebbf7b8bcd4c9dd` |
| `kata-static-4.2.0-amd64.tar.zst` | `b828904fa3f1e49ddd7dc799c72cb1503cd1e772d354c3987c8d4189b2a623a8` |
| `kata-deploy-4.2.0.tgz` (Helm chart) | `52a3e9139e810d58867a7676fb38957870dd09e8b2033e54cebdda7c97598e8c` |

The release API lists these digests. We downloaded the tools tarball and checked its hash ourselves. Kata 4.2.0 publishes the tools tarball for amd64 only.

Source: https://api.github.com/repos/kata-containers/kata-containers/releases/tags/4.2.0

## What the pinned KBS image contains

Read from Trustee v0.22.0 source, not from running the image:

- `kbs/docker/Dockerfile` builds `make AS_FEATURE=coco-as-builtin FEATURES=pkcs11` with `VAULT=true` and `EXTERNAL_PLUGIN=true`.
- On x86_64, `kbs/Cargo.toml` pulls `attestation-service` with `all-verifier`. That set includes `tpm-verifier`, `tdx-verifier`, `snp-verifier`, `az-snp-vtpm-verifier` and `az-tdx-vtpm-verifier`. The s390x build carries only the snp, nvidia and se verifiers.
- The image sets no `ENTRYPOINT` or `CMD`. Run `/usr/local/bin/kbs --config-file <path>`.

## swtpm test environment

`test/e2e/kind-kata-swtpm.sh` (ticket 04) uses the pins above, plus these. Checked on 2026-11-11.

| What | Pin | Why |
|------|-----|-----|
| kind | `v0.33.0`, `kind-linux-amd64` sha256 `aee6151561422756b764a4ae28e7f44cda5af5a9eead3cc9985112b1de8d8e0d` | release asset |
| kind node | `kindest/node:v1.37.0@sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5` | default node of kind v0.33.0 |
| Guest kernel source | Linux `6.18.35` | Kata 4.2.0 `versions.yaml` `assets.kernel.version` |
| AA builder | `docker.io/library/ubuntu:26.04@sha256:6a06111c3b0a8600feadb270aec771dc239bf407b25625f93f44ab00e11f4d3c` | same release as the Kata 4.2.0 guest rootfs (resolute) |
| Rust | `1.95.0` | guest-components v0.22.0 `rust-toolchain.toml` |
| Probe image | `docker.io/library/busybox:1.37.0@sha256:a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec` | pulled in the guest by `verify` |
| Bootstrap Helper builder | `docker.io/library/golang:1.26.4-alpine@sha256:3ad57304ad93bbec8548a0437ad9e06a455660655d9af011d58b993f6f615648` | `cmd/bootstrap-helper/Containerfile` (ticket 06) |
| Test registry | `docker.io/library/registry:3.0.0@sha256:6c5666b861f3505b116bb9aa9b25175e71210414bd010d92035ff64018f9457e` | serves the helper image to the kind node and the guest in `trustee-cvm.sh` |

QEMU, swtpm and tpm2-tools come from the kind node's distribution packages. They are not pinned. Ticket 04's Comments record the versions that ran.

## Updating a pin

Change the row, the source link and the check date in the same commit. If you move Kata, also move Trustee and guest-components to the commits that Kata's `versions.yaml` names.
