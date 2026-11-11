# Withdraw an approval

**Who:** a Security Operator who released their Share and no longer approves that Sealed Bundle or that Trustee CVM. The Infrastructure Operator restarts the CVM. The other Security Operators hold back their Shares.

**Why a restart:** a Share released to a live boot stays valid for that boot (spec §5). You reach the CVM only through the host, so you can't call it back. The Bootstrap Helper keeps accepted Shares in memory only, so a new CVM boot starts with none.

**Mitigates:** *released Shares are irrevocable for a live boot*. The restart removes your Share only if the host cooperates. A hostile host can keep the old CVM collecting, so the step that protects you is step 2: no other Security Operator approves that boot. See `SECURITY_THREAT_MODEL.md`.

## Preconditions

- The Trustee CVM has not published yet. Check:
  ```sh
  trustee-bootstrap status --endpoint "$ENDPOINT"
  ```
  `state` is `COLLECTING`. If `status` no longer answers and the pod's bootstrap-helper init container exited 0, Trustee already holds the config: go to [When a step fails](#when-a-step-fails).
- You know the `boot_id` from that output. Write it down.

## Steps

1. **Security Operator:** tell the Infrastructure Operator and every other Security Operator, through your usual signed channel, that you withdraw. Give the `boot_id`, your Share index and the bundle digest you released for.
2. **Every other Security Operator:** don't run `approve` against that `boot_id`. If you withdraw approval of the bundle itself, delete or rebuild your Operator Policy so a later `approve` can't release for it:
   ```sh
   rm -r ~/trustee-policy
   ```
3. **Infrastructure Operator:** recreate the pod. Deleting it destroys the CVM and its memory, Shares included:
   ```sh
   kubectl delete pod trustee-cvm
   kubectl apply -f trustee-cvm.yaml
   ```
   Use the same rendered `trustee-cvm.yaml` (the one genpolicy wrote) only if the Security Operators still approve its Init-Data and bundle. Otherwise deploy the new one from [Unlock Ceremony](unlock-ceremony.md).
4. **Security Operator:** check the new boot:
   ```sh
   trustee-bootstrap status --endpoint "$ENDPOINT"
   ```
   `boot_id` differs from the one you wrote down, `state` is `COLLECTING`, and `accepted` is `[]`.
5. Run a fresh [Unlock Ceremony](unlock-ceremony.md) when the Security Operators agree to.

## Second-person checks

- A second Security Operator runs step 4 from their own workstation and sees the same new `boot_id` and an empty `accepted` list.
- The Infrastructure Operator shows the pod's new UID: `kubectl get pod trustee-cvm -o jsonpath='{.metadata.uid}'` differs from before step 3.

## When a step fails

- **The helper already published:** too late to withdraw. Trustee runs with that bundle's config. Treat its secrets as released to whatever its resource policy allows. Seal a new config with new keys and secrets ([Seal the config](seal.md)), deploy it, run an Unlock Ceremony, and retire the old pod.
- **Step 4 shows the old `boot_id`:** the host didn't restart the CVM, or it shows you a stale status. `status` is plain HTTP, so the host can fake it. Keep step 2 in force: with no further Shares, the old boot stays locked. Escalate to whoever controls the cluster.
- **Step 4 shows a new `boot_id` with indices in `accepted`:** someone approved the new boot already. Check with the Security Operators whose indices appear. If nobody did, stop all approvals and escalate: a compromised Share may be in use.
- **The pod was started with `--deadline`:** the helper discards the Shares itself when that time passes and fails. Treat it as cleanup only. The host influences the guest clock, so you still need steps 1 to 4.
