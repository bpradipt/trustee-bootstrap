# Key Ceremony

**Who:** the Ceremony Authority runs it. Each Security Operator receives their Share in person. A second person (the witness) watches every step.

**Result:** a Ceremony Manifest (`ceremony.json`) that anyone may read, and one Share file per Security Operator. The bootstrap private key exists only in the memory of the `ceremony split` process and is never written to disk.

**Mitigates:** one operator acting as many (one Share and one Share Commitment per index); a stolen Share (a Share alone unlocks nothing below K). See `SECURITY_THREAT_MODEL.md`.

## Preconditions

- An air-gapped Linux machine with no network interface up, and swap off. Check both:
  ```sh
  ip -brief link show up     # only lo
  swapon --show              # no output
  ```
- The `trustee-bootstrap` binary, verified against `SHA256SUMS` (see [README](README.md)), plus `jq`, `sha256sum` and `base64`.
- One removable medium per Security Operator, and one for the Ceremony Manifest.
- The agreed threshold K and the holder labels. A label becomes the Share file name and appears in `ceremony.json`, so use short names with no `/`, for example `alice`.
- K is at least 2 and at most the number of holders.

## Steps

1. Create a memory-backed working directory, so the Share files never reach a disk:
   ```sh
   sudo mkdir -p /mnt/ceremony
   sudo mount -t tmpfs -o size=1m,mode=0700,uid=$(id -u) tmpfs /mnt/ceremony
   ```
2. Split. For 2 of 3:
   ```sh
   trustee-bootstrap ceremony split --threshold 2 --holders alice,bob,carol --out-dir /mnt/ceremony
   ```
   It prints `key_id <hex>` and `recipient age1...`. Write both down.
3. List the result:
   ```sh
   ls -l /mnt/ceremony
   ```
   You see `ceremony.json` (mode `-rw-r--r--`) and one `<holder>.share` per holder (mode `-rw-------`). Nothing else.
4. Record the manifest digest. The Infrastructure Operator pins this value in the Bootstrap Helper's `--manifest-sha256` argument:
   ```sh
   sha256sum /mnt/ceremony/ceremony.json
   ```
5. Check each Share against its Share Commitment. For each holder:
   ```sh
   h=alice
   echo "sha256:$(jq -r .share /mnt/ceremony/$h.share | base64 -d | sha256sum | cut -d' ' -f1)"
   jq -r --arg h "$h" '.shares[] | select(.holder == $h) | .commitment' /mnt/ceremony/ceremony.json
   ```
   The two lines must be equal.
6. Copy each Share file to its holder's medium only, and keep its mode:
   ```sh
   cp --preserve=mode /mnt/ceremony/alice.share /media/alice/
   ```
   Hand the medium to the holder. Copy `ceremony.json` to the manifest medium.
7. Destroy the working copies and power off:
   ```sh
   sudo umount /mnt/ceremony
   sudo poweroff
   ```
8. Publish `ceremony.json`, its SHA-256, `key_id` and `recipient` to the Infrastructure Operator and every Security Operator, through a channel the cluster host can't change (for example a signed message).

Each Security Operator stores their Share file with mode `0600`, on a machine only they control, and never copies it to the cluster.

## Second-person checks

The witness confirms, and signs the record of:

- step 1: the network and swap checks gave the expected output;
- step 3: the file count is N + 1, and the Share files are `0600`;
- step 4: the published digest equals the one `sha256sum` printed;
- step 5: every Share matched its commitment;
- step 6: each holder received only their own file;
- step 7: the tmpfs is unmounted (`mount | grep /mnt/ceremony` prints nothing) and the machine is off.

## When a step fails

- **`create <file>: ... file exists`** at step 2: the directory was not empty, or a holder label repeats. `ceremony split` never overwrites a file. Unmount, mount a fresh tmpfs, fix the labels, and run step 2 again. Throw away every file from the failed run.
- **`threshold K is below 2`** or **`threshold K is above the N shares`** at step 2: fix `--threshold` and rerun on a fresh tmpfs.
- **A commitment does not match** at step 5: stop. Do not hand out any Share. Unmount, power off, and run the whole Key Ceremony again.
- **A Share file may have been copied** (wrong medium, a photo, a second copy): the Share is compromised. If fewer than K Shares are compromised, the key still holds, but record the incident. If you can't account for K or more, run a new Key Ceremony and follow [Change the roster](roster-change.md).
