# 25: Deploy the Trustee CVM with Trustee's Helm chart

**What to build:** a way to deploy the Trustee CVM from upstream Trustee's Helm chart, `deployment/helm-chart`, and to run the e2e tests against it.

- `deploy/helm/trustee-chart.patch` adds the chart options the Trustee CVM needs: `attestationService.mode`, `kbs.runtimeClassName`, `kbs.strategy`, `kbs.extraInitContainers`, `kbs.configFile`, and the `kbs.readinessProbe` and `kbs.livenessProbe` overrides.
- `deploy/helm/sealed-cvm-values.yaml` and `deploy/helm/helper-service.yaml` describe the pod from `deploy/examples/trustee-cvm.yaml`, as a Deployment.
- `deploy/helm/README.md` gives the Infrastructure Operator's steps and the e2e commands.
- `E2E_DEPLOY=helm` makes `trustee-cvm.sh` and `golden-path.sh` deploy through the chart (`test/e2e/helm.sh`).

**Why:** Trustee's Helm chart is upstream's way to deploy Trustee on Kubernetes. Without the patch, it runs KBS, a gRPC AS and RVPS as three Deployments outside any CVM, and feeds KBS a config and keys from values and Secrets that the host controls.

**Design:** [ADR 0010](../adr/0010-deploy-with-trustees-helm-chart.md). Agreed on 2026-11-22:

- The patch lives in this repository, against one pinned Trustee commit.
- KBS runs the built-in-AS image, so the sealed-config checks still apply.
- One replica, `strategy: Recreate` (ADR 0009 is open).
- genpolicy runs on a first render. A second render adds the annotation through `kbs.podAnnotations`, and must differ from the first by that line only.

**Blocked by:** none

**Status:** done

**Spec:** §7 (the Trustee CVM); `docs/upstream-pins.md`.

- [x] With none of the new options set, the patched chart renders what upstream's renders.
- [x] With `sealed-cvm-values.yaml`, the chart renders one Deployment and one Service: the helper init container and KBS, the manifest and bundle ConfigMaps, a memory `emptyDir`, and no config ConfigMap, key Secret, storage volume, AS or RVPS.
- [x] genpolicy builds a policy for the render, and the second render differs from the first by the annotation only.
- [x] `E2E_DEPLOY=helm test/e2e/trustee-cvm.sh` passes: unlock, exec denied, empty host state volume, AT-17, AT-21, AT-22, AT-24, AT-26, a Recreate rollout, the changed helper arg, both image swaps and AT-11.
- [x] `E2E_DEPLOY=helm test/e2e/golden-path.sh` passes EV-16 to EV-19.
- [x] The default path still passes: `trustee-cvm.sh` and `golden-path.sh`.

## Comments

- **Verified** on the scratch VM (kind + Kata 4.2.0 + swtpm, 4 vCPU, 6 GB, rootful podman, Helm v4.3.1), 2026-11-22, at `092949c`. The runs used these commits before a rebase onto `c0fa24a`. That rebase and a later ADR 0009 link changed only Markdown, so the code and manifests are the ones that ran:
  - **Render.** `helm template` of the patched chart with default values is byte-identical to upstream's at `6b5fd14`. With `sealed-cvm-values.yaml`, it renders one Deployment and one Service. The pod holds init container `bootstrap-helper`, container `kbs`, and volumes `manifest`, `bundle` and `state`.
  - **genpolicy.** Kata 4.2.0's genpolicy panics with `Unsupported field: spec.template.spec.automountServiceAccountToken`, and Kata 4.3.1's `pod.rs` has no such field either. `genpolicy-settings.json` allows the service-account mount whatever the pod says, so the steps drop that line from genpolicy's input. A Kata change could support the field and drop the mount when it is `false`.
  - **Two renders.** The second render differs from the first by the `cc_init_data` line only. genpolicy, run on a render that already has the annotation, reads it back and writes the `[data]` keys in another order (`policy.rego`, `cdh.toml`, `aa.toml`): the same content, another digest. The steps never run genpolicy twice.
  - **Init-Data.** The containers are `bootstrap-helper` and `kbs`. The sandbox name is `^trustee-kbs-[bcdfghjklmnpqrstvwxz2456789]+-[bcdfghjklmnpqrstvwxz2456789]+$`, and the sandbox namespace is `""`, as on the pod path. The image rule from ticket 21 is there.
  - **`E2E_DEPLOY=helm trustee-cvm.sh`** passed every check in box 4. In `recreate`, the rollout never ran two pods at once, the new pod's helper answered `COLLECTING []`, `trustee-kbs` had no ready endpoint, and the same Operator Policies unlocked the new pod.
  - **`E2E_DEPLOY=helm golden-path.sh`** passed EV-16 to EV-19.
  - **Pod path.** `trustee-cvm.sh` and `golden-path.sh` passed at `290f187` and again at `092949c`.
  - KBS v0.22.0 serves `/healthz` (`kbs/src/api_server.rs:187`), so the chart's probes work with scheme HTTPS.
  - `test/e2e/ci.sh go` and `test/e2e/ci.sh lint main` exit 0 at `80da547` and `092949c`. `test/supplychain` first read the values file's `image:` map as image `repository:`. `80da547` fixed the regex and checks image maps.
- **One flake.** At `290f187`, the first `golden-path.sh` run failed EV-18 on a Warning event: Kata's `prepare vm: File exists (os error 17)` on `workload-other`'s sandbox, after which the pod started. The rerun passed, and no later run showed it.
- **Not done:**
  - CI runs only the example pod.
  - Nobody has sent the chart options upstream yet (ADR 0010).
  - With `attestationService.mode: builtin` and no `kbs.configFile`, the chart fails to render, because it can't write a built-in AS config yet. Upstream would need that before it takes the option.
