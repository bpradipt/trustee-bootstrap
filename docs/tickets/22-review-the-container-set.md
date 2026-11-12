# 22: Review the Trustee CVM's container set

**What to build:** the Unlock Ceremony runbook's Init-Data review, part 2 step 1, checks that the agent policy allows exactly two containers, `bootstrap-helper` and `trustee`.

**Why:** [EV-05](../evals/05-weakened-init-data-review.md) ran the review checklist against eight weakened Init-Data files. The checklist caught seven of them. It missed an Init-Data whose pod has one more container, because none of its greps looked at the container set. The extra container used the helper's own image, so no image digest gave it away. "Read the rest of the `policy.rego` entry" was the only guard, and a 2,700-line policy is easy to skim past. An extra container runs inside the TEE next to the helper and Trustee, and the state volume could be mounted into it.

**Decided:** one more grep in the checklist. Each container in the policy data carries an `io.kubernetes.cri.container-name` annotation, so listing them shows the set.

**Blocked by:** none

**Status:** done

**Spec:** §7 (Init-Data and the Kata Agent policy); residual risk *"Init-Data is the single root"*.

- [x] The runbook's checklist lists the container names and says what it should show.
- [x] EV-05's checklist includes the check, and the sidecar variant fails it.

## Comments

- The check doesn't depend on ticket 21. Ticket 21 is about which image a container runs, and this ticket is about how many containers the pod may run.
