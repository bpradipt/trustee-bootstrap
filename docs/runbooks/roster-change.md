# Change the roster

**Who:** the Ceremony Authority, the Infrastructure Operator and every Security Operator on the old and the new roster.

**When:** a Security Operator joins or leaves, a Share is lost or compromised, or you change K.

**Why a fresh Key Ceremony:** the Ceremony Manifest fixes the holders, their Share Commitments, K and the recipient. A change to any of them means a new key pair. The Sealed Bundle is encrypted to the old recipient, so you must seal again. The manifest digest is pinned in Init-Data, so Init-Data and every Operator Policy change too.

**Mitigates:** *roster change requires a full new Key Ceremony, a re-seal, new Init-Data and new Operator Policies*. It also covers a departing Security Operator who keeps a copy of their old Share. See `SECURITY_THREAT_MODEL.md`.

## What the old Shares can still do

K old Shares still decrypt the old `bundle.age`. Anyone who holds K of them and a copy of that bundle can read Trustee's old TLS key and old secrets. So the new bundle must carry new keys and new secrets ([Seal the config](seal.md) always makes new keys), and you rotate every resource secret the old bundle held, at its source.

## Steps

1. **Ceremony Authority:** run the [Key Ceremony](key-ceremony.md) with the new holders and K. Publish the new `ceremony.json`, its SHA-256 and the new `key_id`.
2. **Infrastructure Operator:** seal a new config to the new manifest with [Seal the config](seal.md). Rotate each resource secret at its source first, so the new bundle holds only new values. Publish the new bundle digest and the new `tls.crt`.
3. **Infrastructure Operator:** deploy with the new manifest and bundle: [Unlock Ceremony](unlock-ceremony.md), part 1. Delete the old pod and replace both ConfigMaps:
   ```sh
   kubectl delete pod trustee-cvm
   kubectl create configmap trustee-ceremony-manifest --from-file=ceremony.json --dry-run=client -o yaml | kubectl apply -f -
   kubectl create configmap trustee-sealed-bundle --from-file=bundle.age --dry-run=client -o yaml | kubectl apply -f -
   kubectl apply -f trustee-cvm.yaml
   ```
4. **New Security Operators:** review the new `init.toml`, build a new Operator Policy with your new Share file, and approve: [Unlock Ceremony](unlock-ceremony.md), parts 2 and 3. `policy build` refuses a Share file from the old ceremony.
5. **Workload owners:** replace `kbs_cert` in each workload's Init-Data with the new `tls.crt`.
6. **Every old Security Operator:** delete your old Share file and your old Operator Policy directories, and confirm in writing:
   ```sh
   rm ~/alice.share
   rm -r ~/trustee-policy
   ```
7. **Infrastructure Operator:** delete every copy of the old `bundle.age` and old `ceremony.json` you control, including old ConfigMaps in other namespaces or clusters.

## Second-person checks

- Step 1: the Key Ceremony witness checks as that runbook says. The new `key_id` differs from the old one.
- Step 3: `trustee-bootstrap status --endpoint "$ENDPOINT"` shows the new `key_id`.
- Step 4: each new Security Operator's `policy build` printed the same `init_data_sha256`.
- Step 6: each old Security Operator confirms deletion. Nobody can prove a deletion, so record who confirmed and when.

## When a step fails

- **`approve` says `the Bootstrap Helper has key_id X, the Share file Y`:** the pod still runs the old manifest, or you used an old Share file. Check the ConfigMap and the `--manifest-sha256` value in the rendered pod.
- **The helper fails at start** (pod in `Init:Error`, status never answers): the mounted `ceremony.json` doesn't match the pinned `--manifest-sha256`. Render the pod again with the new manifest's SHA-256 and run genpolicy again.
- **An old Security Operator can't confirm deletion:** count their Share as compromised. While fewer than K old Shares are unaccounted for, the old bundle stays sealed. If K or more are, treat every secret in the old bundle as exposed, which step 2 already rotated.
