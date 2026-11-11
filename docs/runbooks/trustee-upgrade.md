# Upgrade Trustee

**Who:** the Infrastructure Operator prepares and deploys. Every Security Operator reviews and approves again.

**What counts as an upgrade:** a new Trustee (KBS) image, a new Bootstrap Helper image, a new `trustee-bootstrap` release, a Kata or genpolicy change, or any change to Trustee's config, policy, resources or reference values.

**Why it needs a full round:** the Kata Agent policy in Init-Data pins both images and the helper's arguments, so a new image means new Init-Data and a new Init-Data digest. Trustee's config lives only in the Sealed Bundle, so a config change means a new bundle and a new digest. Each Security Operator's Operator Policy names both digests. A restart also loses every runtime admin write (ADR 0002).

**Mitigates:** *Trustee replaced after unlock* (the agent policy pins the images, and Security Operators re-review them), *upstream sample configs are unsafe* (you start again from the release's secure config), and *availability* (you plan the outage). See `SECURITY_THREAT_MODEL.md`.

## Preconditions

- A `trustee-bootstrap` release whose `docs/upstream-pins.md` names the Trustee version you want. The sealed-config checks and `deploy/examples/trustee-config/kbs.toml` match that version only. Don't change the KBS image digest in `trustee-cvm.yaml` by hand.
- The release verified against `SHA256SUMS` (see [README](README.md)) by everyone who runs a command.
- K Security Operators available for the Unlock Ceremony, and an agreed outage window. Workloads can't attest while Trustee is down.
- If you seal a new config: workload owners ready to change `kbs_cert` in their Init-Data. Every seal makes a new TLS key, because the old plaintext is gone ([Seal the config](seal.md)).

## Steps

1. **Infrastructure Operator:** read the release notes and the diff of `deploy/examples/` and `docs/upstream-pins.md` against the release you run now. List what changes: images, config format, helper flags.
2. **Infrastructure Operator:** if the config, the Trustee version or the Ceremony Manifest changes, seal again with [Seal the config](seal.md), using the new release's `kbs.toml`. Publish the new bundle digest and the new `tls.crt`. If nothing in the config changes and the Trustee version stays the same, keep the current `bundle.age` and its digest.
3. **Infrastructure Operator:** build the new Bootstrap Helper image and render the pod from the new release's `deploy/examples/trustee-cvm.yaml`, then run genpolicy and extract `init.toml`: [Unlock Ceremony](unlock-ceremony.md), part 1, steps 1 to 5. Don't apply the pod yet.
4. **Every Security Operator:** review the new `init.toml` and build a new Operator Policy into a new directory, for example `~/trustee-policy-v2`: [Unlock Ceremony](unlock-ceremony.md), part 2, steps 1 to 3. Keep the old directory until step 7 passes, so a rollback needs no new review.
5. **Infrastructure Operator:** at the start of the outage window, replace the pod and the bundle ConfigMap:
   ```sh
   kubectl delete pod trustee-cvm
   kubectl create configmap trustee-sealed-bundle --from-file=bundle.age --dry-run=client -o yaml | kubectl apply -f -
   kubectl apply -f trustee-cvm.yaml
   ```
6. **Security Operators:** run the Unlock Ceremony against the new pod with the new Operator Policy: [Unlock Ceremony](unlock-ceremony.md), part 3.
7. **Infrastructure Operator and workload owners:** check that Trustee is Ready and that a workload with the current `kbs_cert` attests and gets its resource:
   ```sh
   kubectl wait --for=condition=Ready pod/trustee-cvm --timeout=600s
   ```

## Second-person checks

- Step 1: a second person reads the same diff and agrees on the list of changes.
- Step 4: each Security Operator's `policy build` printed the same `init_data_sha256`. Compare them over your signed channel.
- Step 6: before the K-th Share, every index in `trustee-bootstrap status`'s `accepted` list belongs to someone who approved the upgrade. After it, the bootstrap-helper init container exited 0.

## When a step fails

- **`seal` refuses the old tree with the new release:** the config format changed. Build the tree from the new release's `kbs.toml`. Never weaken a check to get past it.
- **The new pod never reaches the helper** (status doesn't answer): run `kubectl describe pod trustee-cvm`. `CreateContainerRequest is blocked by policy` in the events means the rendered pod and its Init-Data disagree. Render and run genpolicy again from the same files, then repeat the review in step 4.
- **An `approve` prints `not accepted`:** follow [Unlock Ceremony](unlock-ceremony.md), *When a step fails*.
- **Roll back:** delete the new pod, put the old `bundle.age` back in the ConfigMap, apply the old rendered `trustee-cvm.yaml`, and run an Unlock Ceremony with the old Operator Policy directories. This works only if each Security Operator still approves the old bundle. An old bundle on a fresh boot is a deliberate approval, not a restart (spec AT-10).
