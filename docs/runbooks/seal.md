# Seal the config

**Who:** the Infrastructure Operator, on a controlled sealing machine. A second person (the witness) watches every step.

**Result:** a Sealed Bundle (`bundle.age`), its SHA-256 (the Approved Bundle digest), and Trustee's public TLS certificate for workloads. The plaintext config, including Trustee's TLS private key and every resource secret, is gone from the sealing machine.

**Mitigates:** *the Infrastructure Operator sees the plaintext config* (ADR 0008). Nothing in the protocol detects a kept copy, so this runbook is the only guard. It also covers *`kbs_cert` adds a root* (step 3 names a cluster-internal host) and *upstream sample configs are unsafe* (step 2 starts from the repo's secure config, and `seal` refuses an insecure one). See `SECURITY_THREAT_MODEL.md`.

## Preconditions

- A sealing machine that only the Infrastructure Operator controls, with swap off (`swapon --show` prints nothing), no backup agent, and no sync client running. Disconnect it from the network once you have the files below.
- The `trustee-bootstrap` binary, verified against `SHA256SUMS` (see [README](README.md)), plus `openssl` and `sha256sum`.
- `ceremony.json` from the [Key Ceremony](key-ceremony.md). Its SHA-256 equals the published value:
  ```sh
  sha256sum ceremony.json
  ```
- `deploy/examples/trustee-config/kbs.toml` from the release tag. It assumes Trustee sees the tree at `/trustee/config`, the Bootstrap Helper's `--out` in `deploy/examples/trustee-cvm.yaml`.
- Trustee's resource policy (Rego) and its resources and RVPS reference values, written down before the session.
- A cluster-internal host name or private IP for Trustee's certificate, for example `trustee.default.svc.cluster.local`. No public CA may certify it.

## Steps

1. Create a memory-backed working directory. Every secret below lives only here:
   ```sh
   sudo mkdir -p /mnt/seal
   sudo mount -t tmpfs -o size=8m,mode=0700,uid=$(id -u) tmpfs /mnt/seal
   cd /mnt/seal
   mkdir -p tree/storage/kbs tree/storage/repository tree/storage/reference_value
   cp /path/to/release/deploy/examples/trustee-config/kbs.toml tree/
   ```
2. Keep `kbs.toml` as it is. If your site needs a change, keep `insecure_http = false`, `insecure_header_jwk = false`, `authorization_mode = "AuthenticatedAuthorization"` and the `LocalFs` storage backend; `seal` refuses a tree without them.
3. Create Trustee's TLS key and a self-signed leaf certificate for the cluster-internal name. The guest uses rustls, which refuses a CA certificate as a server certificate, so keep `CA:FALSE`:
   ```sh
   host=trustee.default.svc.cluster.local
   openssl ecparam -name prime256v1 -genkey -noout -out tree/tls.key
   openssl req -new -key tree/tls.key -subj "/CN=$host" -out tls.csr
   printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:%s\n' "$host" >tls.ext
   openssl x509 -req -in tls.csr -signkey tree/tls.key -days 365 -extfile tls.ext -out tree/tls.crt
   ```
4. Create the AS token signer (P-256) and the admin key. Keep only the admin public key, unless your site has a vault for the private half. Runtime admin writes are lost on every restart anyway (ADR 0002):
   ```sh
   openssl ecparam -name prime256v1 -genkey -noout -out tree/as-signer.key
   openssl req -x509 -new -key tree/as-signer.key -subj "/CN=Trustee AS signer" -days 365 -out tree/as-signer.crt
   openssl genpkey -algorithm ed25519 | openssl pkey -pubout -out tree/admin.pub
   ```
5. Add the resource policy at its exact key, then the resources and reference values. A `/` in a resource path becomes the literal four characters `\x2F` in the file name:
   ```sh
   cp /path/to/resource-policy.rego tree/storage/kbs/resource-policy.rego
   printf '%s' "$SECRET_VALUE" >'tree/storage/repository/default\x2Fapp\x2Fsecret'
   printf '{"version":"0.1.0","name":"%s","expiration":"%s","value":%s}' \
     trusted_aks "$(date -u -d '+1 year' +%Y-%m-%dT%H:%M:%SZ)" '["<AK PEM body>"]' >tree/storage/reference_value/trusted_aks
   ```
   The reference values your workloads' TEE type needs are in `docs/claim-profiles.md`.
6. Seal. `seal` runs the sealed-config checks, then encrypts the tree to the Ceremony Manifest's recipient and prints the bundle's SHA-256:
   ```sh
   trustee-bootstrap seal --manifest /path/to/ceremony.json --output bundle.age tree
   ```
7. Check the bundle and keep the public parts. The bundle travels in a ConfigMap, so it must be at most 1048576 bytes:
   ```sh
   sha256sum bundle.age
   stat -c %s bundle.age
   cp bundle.age tree/tls.crt /path/to/outbox/
   ```
8. Destroy the plaintext:
   ```sh
   cd /
   sudo umount /mnt/seal
   ```
9. Publish the bundle digest to every Security Operator through a channel the cluster host can't change. Give `bundle.age` to the cluster as the `trustee-sealed-bundle` ConfigMap ([Unlock Ceremony](unlock-ceremony.md)) and `tls.crt` to workload owners: each workload adds it as `kbs_cert` in its Init-Data.

## Second-person checks

The witness confirms, and signs the record of:

- the swap, backup and network checks before step 1;
- step 2: `kbs.toml` is the release file, or its diff from that file keeps the four settings;
- step 3: `openssl x509 -in tree/tls.crt -noout -ext subjectAltName,basicConstraints` shows only the cluster-internal name and `CA:FALSE`;
- step 6: `seal` exited 0 and printed one 64-character hex digest;
- step 7: `sha256sum` printed the same digest, and the size is at most 1048576;
- step 8: `mount | grep /mnt/seal` prints nothing, and the outbox holds only `bundle.age` and `tls.crt`;
- step 9: the published digest equals the step 6 digest.

## When a step fails

- **`sealed-config checks: ...`** at step 6: `seal` names the failed check, for example `[attestation_token] insecure_header_jwk is true`, `resource policy ... is KBS's built-in default`, or a signer file that is missing or that `trusted_certs_paths` does not list. Fix the tree in `/mnt/seal` and run step 6 again. `seal` wrote no bundle.
- **`parse recipient`** at step 6: `ceremony.json` is damaged or is not a Ceremony Manifest. Get it again and recheck its digest.
- **The bundle is over 1048576 bytes:** the Bootstrap Helper refuses it. Move large resources out of the bundle and seal again.
- **A plaintext copy may survive** (an editor swap file, a terminal log, a file written outside `/mnt/seal`, swap that was on): treat every secret in the tree as known to someone else. Generate new keys and secrets, seal again, and publish only the new digest. Tell Security Operators not to approve the old digest.
- **You must change the config later:** the plaintext is gone, so start this runbook again from step 1 with new keys. A new `tls.key` means every workload must update its `kbs_cert` (spec §1). Plan that rollout first.
