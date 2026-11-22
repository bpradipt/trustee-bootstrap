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

**Status:** in-progress

**Spec:** §7 (the Trustee CVM); `docs/upstream-pins.md`.

- [ ] With none of the new options set, the patched chart renders what upstream's renders.
- [ ] With `sealed-cvm-values.yaml`, the chart renders one Deployment and one Service: the helper init container and KBS, the manifest and bundle ConfigMaps, a memory `emptyDir`, and no config ConfigMap, key Secret, storage volume, AS or RVPS.
- [ ] genpolicy builds a policy for the render, and the second render differs from the first by the annotation only.
- [ ] `E2E_DEPLOY=helm test/e2e/trustee-cvm.sh` passes: unlock, exec denied, empty host state volume, AT-17, AT-21, AT-22, AT-24, AT-26, a Recreate rollout, the changed helper arg, both image swaps and AT-11.
- [ ] `E2E_DEPLOY=helm test/e2e/golden-path.sh` passes EV-16 to EV-19.
- [ ] The default path still passes: `trustee-cvm.sh` and `golden-path.sh`.

## Comments
