# Trustee CVM from Trustee's Helm chart

These files deploy the Trustee CVM from upstream Trustee's Helm chart, `deployment/helm-chart` in [confidential-containers/trustee](https://github.com/confidential-containers/trustee). You get the pod from [`deploy/examples/trustee-cvm.yaml`](../examples/trustee-cvm.yaml) as a Deployment with one replica. [ADR 0010](../../docs/adr/0010-deploy-with-trustees-helm-chart.md) says why the chart needs a patch and why the patch lives here.

| File | What it holds |
|---|---|
| `trustee-chart.patch` | Six chart options: `attestationService.mode`, `kbs.runtimeClassName`, `kbs.strategy`, `kbs.extraInitContainers`, `kbs.configFile`, and the `kbs.readinessProbe` and `kbs.livenessProbe` overrides. Leave them unset and the chart renders what upstream's renders. |
| `sealed-cvm-values.yaml` | The chart values for the Trustee CVM. |
| `helper-service.yaml` | The Service that Security Operators use to reach the Bootstrap Helper. |

The patch applies to Trustee commit `6b5fd14ef69d4ad634295f35a0759e2a3c7c7025`. `test/e2e/helm.sh` pins that commit and Helm v4.3.1, and [`docs/upstream-pins.md`](../../docs/upstream-pins.md) gives their sources.

## Deploy

These steps replace steps 3 to 7 in part 1 of the [Unlock Ceremony runbook](../../docs/runbooks/unlock-ceremony.md). Do its steps 1 and 2 first, which build the helper image and create the two ConfigMaps. You also need Helm, git, and the genpolicy files from the runbook's preconditions in `$GP`. Run each command from your trustee-bootstrap checkout.

1. Fetch the chart at the pinned commit and apply the patch. Helm wants every dependency present, so `helm dependency build` downloads the PostgreSQL and Valkey charts in `Chart.lock`, though the Trustee CVM runs neither:
   ```sh
   git init -q trustee-chart
   git -C trustee-chart fetch --depth 1 https://github.com/confidential-containers/trustee 6b5fd14ef69d4ad634295f35a0759e2a3c7c7025
   git -C trustee-chart checkout -q FETCH_HEAD
   git -C trustee-chart apply "$PWD/deploy/helm/trustee-chart.patch"
   CHART=trustee-chart/deployment/helm-chart
   helm dependency build "$CHART"
   ```
2. Fill in the values. Then set `runtimeClassName` in `values.yaml` to your TEE's Kata runtime class:
   ```sh
   MANIFEST_SHA256=$(sha256sum ceremony.json | cut -d' ' -f1)
   KBS_IMAGE=$(awk '$1 == "kbs_image:" { print $2 }' versions.yaml)
   sed "s|@HELPER_IMAGE@|$HELPER_IMAGE|; s|@MANIFEST_SHA256@|$MANIFEST_SHA256|; s|@KBS_REPOSITORY@|${KBS_IMAGE%%:*}|; s|@KBS_TAG@|${KBS_IMAGE#*:}|" \
     deploy/helm/sealed-cvm-values.yaml >values.yaml
   cp deploy/examples/init-data.toml init-data.toml
   ```
3. Render the chart and run genpolicy on the render. Kata 4.2.0's genpolicy stops with `Unsupported field: spec.template.spec.automountServiceAccountToken`, so delete that one line from its input. genpolicy's settings allow the service-account mount whatever the pod says, so you get the same policy:
   ```sh
   helm template trustee "$CHART" -f values.yaml >render.yaml
   sed '/^ *automountServiceAccountToken: false$/d' render.yaml >genpolicy.yaml
   patch -o rules.rego "$GP/rules.rego" deploy/genpolicy/rules.rego.patch
   "$GP/genpolicy" -y genpolicy.yaml -p rules.rego -j "$GP" --initdata-path=init-data.toml
   ```
4. Extract the Init-Data that the CVM will measure, and write its annotation into a second values file:
   ```sh
   python3 -c 'import base64,gzip,re,sys; m=re.search(r"cc_init_data: *\"?([A-Za-z0-9+/=]+)", open("genpolicy.yaml").read()); sys.stdout.buffer.write(gzip.decompress(base64.b64decode(m.group(1))))' >init.toml
   python3 -c 'import re; m=re.search(r"(\S*cc_init_data): *\"?([A-Za-z0-9+/=]+)", open("genpolicy.yaml").read()); print(f"kbs:\n  podAnnotations:\n    {m.group(1)}: \"{m.group(2)}\"")' >initdata-values.yaml
   ```
5. Render again with the annotation, and check that nothing else changed. Helm installs this second render, and genpolicy saw the first:
   ```sh
   helm template trustee "$CHART" -f values.yaml -f initdata-values.yaml >trustee-cvm.yaml
   grep -v 'cc_init_data:' trustee-cvm.yaml | diff - render.yaml && echo "only the annotation differs"
   ```
   Don't run genpolicy on `trustee-cvm.yaml`. It reads the annotation back and reorders the Init-Data's keys, and the digest changes.
6. Send `init.toml`, `HELPER_IMAGE` and `trustee-cvm.yaml` to every Security Operator. Part 2 of the runbook applies with two differences in `init.toml`: the containers are `bootstrap-helper` and `kbs`, and the sandbox name is a pattern, `^trustee-kbs-…-…$`, because the Deployment's ReplicaSet names the pod.
7. Install, and find the endpoint for the Security Operators:
   ```sh
   kubectl apply -f deploy/helm/helper-service.yaml
   helm install trustee "$CHART" -f values.yaml -f initdata-values.yaml
   NODE_IP=$(kubectl get node -o jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}')
   NODE_PORT=$(kubectl get service trustee-bootstrap-helper -o jsonpath='{.spec.ports[0].nodePort}')
   echo "ENDPOINT=http://$NODE_IP:$NODE_PORT"
   ```

Workloads reach the unlocked Trustee through the chart's Service, `trustee-kbs`. When you seal, give Trustee a certificate that names `trustee-kbs.<namespace>.svc.cluster.local` ([seal runbook](../../docs/runbooks/seal.md)).

## After the unlock

- Kubernetes replaces the pod after `kubectl rollout restart`, a node drain or an eviction. With `strategy: Recreate`, the old pod stops first, and Trustee serves nothing until K Security Operators approve the new pod. Their Operator Policies still match it while the Init-Data and the bundle stay the same.
- A `helm upgrade` that changes a container, an arg, an image or a mount changes the policy. Repeat steps 3 to 6 before you upgrade.
- Keep `replicaCount: 1` until [ADR 0009](../../docs/adr/0009-trustee-availability.md) chooses how several replicas unlock.

## Run the e2e tests with the chart

On the cluster from `kind-kata-swtpm.sh up`, set `E2E_DEPLOY=helm`:

```sh
export E2E_ENGINE=podman
test/e2e/kind-kata-swtpm.sh up                         # once
E2E_DEPLOY=helm test/e2e/trustee-cvm.sh                # the AT checks, plus a Recreate rollout
E2E_DEPLOY=helm test/e2e/golden-path.sh >transcript.txt   # EV-16 to EV-19
```

`test/e2e/helm.sh` runs steps 1 to 7 above. It fetches the chart and Helm into `$E2E_CACHE` and checks Helm's sha256. The negative checks apply a changed render with `kubectl`, as a hostile host would. CI, `demo.sh` and the eval scripts run only the example pod.
