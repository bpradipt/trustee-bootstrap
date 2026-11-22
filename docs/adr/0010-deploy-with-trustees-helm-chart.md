# Deploy the Trustee CVM with Trustee's Helm chart, patched here

Upstream Trustee ships a Helm chart, `deployment/helm-chart`. It runs KBS, a gRPC Attestation Service and RVPS as three Deployments, sets no runtime class, and renders KBS's config and keys from values and Secrets. The Trustee CVM needs the opposite: one CVM that holds Trustee's whole state (ADR 0002), with its config and keys coming only from the Sealed Bundle.

We deploy through that chart with `deploy/helm/trustee-chart.patch`. The patch adds options any confidential deployment of KBS can use, and none of them names trustee-bootstrap:

- `attestationService.mode: builtin` skips the AS and RVPS Deployments and KBS's `wait-for-as` init container. KBS runs the built-in-AS image, as in our example pod, so the sealed-config checks in `pkg/verifier` still apply.
- `kbs.configFile` points KBS at the tree the Bootstrap Helper publishes. With it set, the chart renders no config and mounts no key Secret, storage volume or nebula CA volume, so the host supplies no file that Trustee reads.
- `kbs.runtimeClassName`, `kbs.extraInitContainers`, `kbs.strategy` and the probe overrides carry the rest of the example pod.

With none of them set, the chart renders what upstream's renders, byte for byte. `deploy/helm/sealed-cvm-values.yaml` sets them for the Trustee CVM: one replica, because [ADR 0009](0009-trustee-availability.md) is undecided, and `strategy: Recreate`, so the helper Service never routes to a pod whose helper has exited.

genpolicy needs the rendered pod, and the pod needs genpolicy's annotation, so the Infrastructure Operator renders twice. The second render passes the annotation in through the chart's `kbs.podAnnotations`, and must differ from the first by that line only.

The patch lives in this repository so that the whole deployment sits in one place. It targets one pinned Trustee commit and applies there unchanged, so it can go upstream as pull requests later.

## Considered Options

- **Send the options upstream first:** deferred. We want the deployment in one repository now, and the patch already applies to upstream's tree.
- **Vendor a copy of the chart:** rejected. A copy drifts from upstream without anyone noticing. A patch that fails to apply makes the drift visible.
- **Patch the rendered output with a Helm post-renderer:** rejected. The options would exist only in our tooling, and an upstream user could not set them.
- **KBS, AS and RVPS as three containers in one CVM:** rejected for now. The guest would pull three images, and the sealed-config checks would have to cover the AS and RVPS configs too.
- **Each component in its own CVM:** rejected. KBS calls the AS over gRPC in plain HTTP across the host's network, and each CVM would need its own Unlock Ceremony.
