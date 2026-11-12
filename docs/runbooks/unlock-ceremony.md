# Unlock Ceremony

**Who:** the Infrastructure Operator deploys the Trustee CVM (part 1). Each Security Operator reviews it and builds their Operator Policy (part 2), then releases their Share (part 3). You need K Security Operators.

**Result:** the Bootstrap Helper accepts K Shares, unseals the Approved Bundle into guest memory and exits; Trustee starts.

**Mitigates:** *Init-Data is the single root* (part 2 reviews it, not only its hash), *host swaps the Ceremony Manifest* (part 2 checks the pinned digest), *bundle rollback* (each Operator Policy names one bundle digest), *claim profiles cover only what was tested* and *TPM/swtpm gives no confidentiality* (part 2, step 3). See `SECURITY_THREAT_MODEL.md`.

## Go/no-go

Today no claim profile has passed a real-TEE run (`docs/claim-profiles.md`), so `policy build` accepts a TEE type only with `--allow-untested-profiles`, and the result is not a production Operator Policy. Don't unlock a Trustee that holds production secrets until a real-TEE run passes and the release marks that TEE type tested (`SECURITY_THREAT_MODEL.md`, Go/no-go). The commands below show `--allow-untested-profiles` because every TEE type needs it in this release.

## Part 1: deploy the Trustee CVM (Infrastructure Operator)

### Preconditions

- `ceremony.json` and its published SHA-256 from the [Key Ceremony](key-ceremony.md); `bundle.age` and its published digest from [Seal the config](seal.md).
- A checkout of the release tag (for `deploy/examples/` and `cmd/bootstrap-helper/Containerfile`), `podman`, `kubectl` for the cluster, and an image registry the cluster pulls from.
- genpolicy, `rules.rego` and `genpolicy-settings.json` from the pinned Kata tools tarball in `docs/upstream-pins.md`, checked against its sha256. Here `$GP` is the directory that holds them.
- A Kata runtime class for your TEE. The example pod uses `kata-qemu-coco-dev-tpm` (swtpm). Change `runtimeClassName` in your copy of `trustee-cvm.yaml` before step 4.

### Steps

1. Build the Bootstrap Helper image and push it. The build is reproducible, so a second person can rebuild it and get the same digest:
   ```sh
   podman build --timestamp 0 --identity-label=false -f cmd/bootstrap-helper/Containerfile -t bootstrap-helper .
   podman push --digestfile helper-digest bootstrap-helper "$REGISTRY/trustee-bootstrap/bootstrap-helper:$VERSION"
   HELPER_IMAGE=$REGISTRY/trustee-bootstrap/bootstrap-helper@$(cat helper-digest)
   ```
2. Create the two ConfigMaps. Both are untrusted: the helper checks the manifest against its pinned digest, and each Share names the bundle digest.
   ```sh
   kubectl create configmap trustee-ceremony-manifest --from-file=ceremony.json --save-config
   kubectl create configmap trustee-sealed-bundle --from-file=bundle.age --save-config
   ```
3. Render the pod:
   ```sh
   MANIFEST_SHA256=$(sha256sum ceremony.json | cut -d' ' -f1)
   sed "s|@HELPER_IMAGE@|$HELPER_IMAGE|; s|@MANIFEST_SHA256@|$MANIFEST_SHA256|" deploy/examples/trustee-cvm.yaml >trustee-cvm.yaml
   cp deploy/examples/init-data.toml init-data.toml
   ```
   The helper hands the published tree to Trustee's UID and GID, pinned as `--owner-uid=0` and `--owner-gid=0`: the pinned KBS image runs as root. If your Trustee image runs as another user, change both args in your copy before step 4.
4. Run genpolicy. It writes the Kata Agent policy into the Init-Data and puts the Init-Data into the pod's `cc_init_data` annotation:
   ```sh
   "$GP/genpolicy" -y trustee-cvm.yaml -p "$GP/rules.rego" -j "$GP" --initdata-path=init-data.toml
   ```
5. Extract the Init-Data TOML that the CVM will measure. Security Operators review this file, not `init-data.toml`, because genpolicy rewrites it:
   ```sh
   python3 -c 'import base64,gzip,re,sys; m=re.search(r"cc_init_data: *\"?([A-Za-z0-9+/=]+)", open("trustee-cvm.yaml").read()); sys.stdout.buffer.write(gzip.decompress(base64.b64decode(m.group(1))))' >init.toml
   ```
6. Send `init.toml`, `HELPER_IMAGE` and the rendered `trustee-cvm.yaml` to every Security Operator.
7. Deploy and find the endpoint that Security Operators use:
   ```sh
   kubectl apply -f trustee-cvm.yaml
   NODE_IP=$(kubectl get node -o jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}')
   NODE_PORT=$(kubectl get service trustee-bootstrap-helper -o jsonpath='{.spec.ports[0].nodePort}')
   echo "ENDPOINT=http://$NODE_IP:$NODE_PORT"
   ```
   Send the endpoint to every Security Operator. The pod stays not Ready until the unlock. The helper's Service publishes not-ready addresses, so Security Operators still reach the helper.

### Second-person checks

- A second person rebuilds the helper image from the same tag with the step 1 command and gets the same digest.
- `grep -c -- "--manifest-sha256=$MANIFEST_SHA256" trustee-cvm.yaml` prints `1`.

## Part 2: review and build your Operator Policy (each Security Operator)

### Preconditions

- Your Share file, mode `0600`, on your own workstation, and `trustee-bootstrap` verified against `SHA256SUMS`.
- `ceremony.json` with the published SHA-256, the published bundle digest, and `init.toml` from part 1.
- The reference values for your TEE type, as a JSON object of arrays (`docs/claim-profiles.md` lists the names). For swtpm: `{"trusted_aks": ["<AK PEM body>"], "tpm_pcr11": ["<64 zeros>"]}`.

### Steps

1. Review `init.toml`. Check each item, and stop if any differs:
   ```sh
   sha256sum ceremony.json                                  # the published value
   grep -o -- '--manifest-sha256=[0-9a-f]*' init.toml | sort -u   # the same value
   grep -o -- '--owner-[ug]id=[0-9]*' init.toml | sort -u        # Trustee's UID and GID: 0 for the pinned KBS image
   grep -o 'bootstrap-helper@sha256:[0-9a-f]*' init.toml | sort -u  # HELPER_IMAGE's digest
   grep -o 'key-broker-service[^"]*' init.toml | sort -u   # the KBS digest in docs/upstream-pins.md
   grep -n 'default ExecProcessRequest\|default ReadStreamRequest' init.toml  # both := false
   grep -A2 '"ExecProcessRequest": {' init.toml             # allowed_commands and regex both []
   grep -n '"ReadStreamRequest"' init.toml                  # false
   grep -n 'url = ' init.toml                                # http://127.0.0.1:8081 only
   grep -o '"io.kubernetes.cri.container-name": "[^"]*"' init.toml | sort -u   # bootstrap-helper and trustee, nothing else
   ```
   Read the rest of the `policy.rego` entry as well. A hash proves only that every Security Operator saw the same file.
2. Build your Operator Policy. It computes the Init-Data digest from the file you reviewed, and checks your Share against the Ceremony Manifest:
   ```sh
   trustee-bootstrap policy build --init-data init.toml --reference-values rv.json \
     --accept-tee tpm --allow-untested-profiles \
     --bundle-sha256 "$BUNDLE_SHA256" --manifest ceremony.json \
     --share-file alice.share --out-dir ~/trustee-policy
   ```
   It prints `init_data_sha256 <hex>`.
3. Accept only the TEE type the Trustee CVM runs on. Leave out `--allow-untested-profiles` for production; see [Go/no-go](#gono-go).

### Second-person checks

- All Security Operators compare their `init_data_sha256` over a signed channel. The values must be equal.
- A second Security Operator repeats step 1 on their own copy of `init.toml`.

## Part 3: release your Share (each Security Operator, one after another)

### Preconditions

- Your Operator Policy from part 2.
- `podman` or `docker` able to pull the pinned KBS image in `docs/upstream-pins.md`, or a native `kbs` for `--kbs-binary`.
- `XDG_RUNTIME_DIR` on a tmpfs. The Operator Verifier refuses to write its run directory anywhere else. Check with `df --output=fstype "$XDG_RUNTIME_DIR"`.

### Steps

1. Check the helper:
   ```sh
   trustee-bootstrap status --endpoint "$ENDPOINT"
   ```
   `key_id` equals the one in `ceremony.json`, `state` is `COLLECTING`, and your index is not in `accepted`.
2. Release your Share. The audit records go to `approve-audit.log`:
   ```sh
   trustee-bootstrap approve --endpoint "$ENDPOINT" --policy ~/trustee-policy --share-file alice.share 2>>approve-audit.log
   ```
   It prints `accepted` once the helper accepted your Share. That does not mean Trustee runs yet. Nor does it mean one CVM: a host that holds the relay can pass your Share to up to four CVMs that run the same approved Init-Data and bundle (`SECURITY_THREAT_MODEL.md`, residual risks).
3. Check again:
   ```sh
   trustee-bootstrap status --endpoint "$ENDPOINT"
   ```
   Your index is in `accepted`. After the K-th Share the helper publishes and exits within seconds, so `status` stops answering with `connect: connection refused`.
4. Infrastructure Operator, after the K-th Share:
   ```sh
   kubectl wait --for=condition=Ready pod/trustee-cvm --timeout=600s
   ```
   Trustee pulls its image inside the guest first, so this can take a few minutes.

### Second-person checks

- Another Security Operator runs step 3 and sees your index in `accepted`, under the same `boot_id`. After the K-th Share, they check instead that the bootstrap-helper init container exited 0: `kubectl get pod trustee-cvm -o jsonpath='{.status.initContainerStatuses[0].state.terminated.exitCode}'` prints `0`.
- Your `approve-audit.log` ends with `"msg":"approve_result"` and `"accepted":true`.

## When a step fails

- **`approve` fails with `relay ended: ... Share not accepted`:** your Share did not reach the helper, or the helper refused it. Run `status`:
  - Your index is in `rejected`: the helper got your Share and refused it. Usually the mounted bundle is not the one your Operator Policy names (spec AT-09, AT-10). Stop. Compare the bundle ConfigMap's SHA-256 with the published digest, and don't retry until they match.
  - Your index is not in `rejected`: your Operator Verifier refused to release, because the CVM's evidence did not match your Operator Policy: other Init-Data, other reference values, or debug on. Stop and compare `init_data_sha256` with the other Security Operators. Don't rebuild your policy to fit the CVM.
- **`open relay: ... 409`:** another relay is open. Security Operators go one at a time; wait and retry. If it persists, someone holds the relay. Ask the Infrastructure Operator to restart the pod, which needs a new Unlock Ceremony.
- **`index N already accepted this boot`:** your Share is in. Nothing to do.
- **`the Bootstrap Helper has key_id X, the Share file Y`:** the CVM runs another Key Ceremony's manifest. Stop and escalate.
- **`start Operator Verifier: ...`:** the problem is on your workstation. `is not on tmpfs` means fix `XDG_RUNTIME_DIR`; an engine or pull error means fix podman or docker. Nothing reached the CVM.
- **`status` never answers** after part 1, step 7: run `kubectl describe pod trustee-cvm`. `Init:Error` with the helper exited 1 means the mounted `ceremony.json` does not match `--manifest-sha256` (spec AT-11), or the bundle is over 1 MiB. `CreateContainerRequest is blocked by policy` means the rendered pod and its Init-Data disagree; render and run genpolicy again, and repeat part 2.
- **The K-th `approve` fails and the init container exited 1:** the helper refused to publish, for example because the bundle failed the sealed-config checks, or the `--deadline` passed. Recreate the pod and run a new Unlock Ceremony. If it fails the same way, seal the config again.
- **The pod is not Ready after the helper exited 0:** run `kubectl describe pod trustee-cvm`. A `ttrpc err: Receive packet timeout` event on the trustee container is a Kata Agent timeout under load, and the kubelet retries it. Anything else means Trustee failed to start from the published tree. The Kata Agent policy denies `kubectl logs` there, so test each config on a dev cluster before you seal it for production.
