# 19: Keep sealed secrets out of shell history

**What to build:** the seal runbook has the Infrastructure Operator type each resource secret at a `read -rs` prompt and `unset` it after use, and the witness checks the shell history for it.

**Why:** [EV-08](../evals/08-ceremonies-leave-no-secret.md) walked the Key Ceremony and seal runbooks in an interactive bash with Ubuntu's default `.bashrc`, then searched the disk for every secret the walk handled.

- Step 5 of the seal runbook used `$SECRET_VALUE` but never said how to set it. An operator sets it the obvious way, `SECRET_VALUE=<value>` at the prompt.
- The shell then shows the value on the terminal and saves the line in `~/.bash_history`. That file sits on the sealing machine's disk, outside the tmpfs that step 8 unmounts.
- ADR 0008 trusts the Infrastructure Operator to destroy the plaintext after sealing. A history file survives that step, and nothing else in the design can detect a copy. Only the runbook guards against it.

**Decided:**

- A runbook change only: the CLI never sees the value, so no code changes.
- Use `read -rs`, which keeps the value off the screen and out of the history file, then `unset` the variable.
- A witness check for step 5: `history | grep SECRET_VALUE` shows only the `read`, `printf` and `unset` lines.

**Blocked by:** none

**Status:** done

**Spec:** ADR 0008; [seal.md](../runbooks/seal.md) step 5; residual risk *"the Infrastructure Operator sees the plaintext config"*.

- [x] seal.md step 5 reads each secret with `read -rs` and unsets it.
- [x] The witness checks step 5 in the shell history.
- [x] EV-08 passes.

## Comments

- **Before the fix.** On the scratch VM, EV-08 found the canary in `~/.bash_history` at line 24, `SECRET_VALUE=CANARY-…`. It also found the value in the captured terminal output, which stands in for what the terminal shows and what a terminal logger or scrollback keeps.
- **After the fix.** With step 5 using `read -rs`, the history holds only `read -rs SECRET_VALUE`, the `printf` line and `unset SECRET_VALUE`. The terminal capture holds no canary.
- **Coverage.** The search covered every file on the root file system and the system and user journals. It excluded the Share files the runbook writes on purpose, and Go module caches, which carry age's own test identities.
