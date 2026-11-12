# EV-08: Ceremonies leave no secret on disk

**Category:** operator mistake
**Runs on:** the scratch VM, playing the Key Ceremony machine and then the sealing machine; `test/e2e/evals-offline.sh ev08`
**Covers:** residual risk "the Infrastructure Operator sees the plaintext config"; condition 7; asset requirements for the bootstrap private key and the plaintext config; [key-ceremony.md](../runbooks/key-ceremony.md); [seal.md](../runbooks/seal.md); ADR 0008

## Setup

- A fresh VM with swap off, the release binaries and the tools both runbooks list.
- A canary resource secret, `CANARY-<32 random hex>`.
- A checker shell that holds every search string in memory only: the canary, and each Share string, read from the tmpfs before the runbook unmounts it.

## Action

1. Walk key-ceremony.md steps 1 to 7 as a person would, in an interactive shell. Skip the `poweroff`.
2. Walk seal.md steps 1 to 8. Enter the canary the way step 5 says.
3. From the checker shell, search for each string, for the bodies of `tls.key` and `as-signer.key`, and for an age identity (`AGE-SECRET-KEY-1` and 50 more characters) in:
   - every file on the root file system, shell history files included;
   - `journalctl`, system and user.

   The PEM headers alone (`BEGIN EC PRIVATE KEY`) appear in too many unrelated files to search for. The search leaves out the Share files the runbook writes on purpose, and Go module caches, which hold age's own test identities.

## Expected

- No search finds a match.
- Every witness check in both runbooks passes.

## Notes

seal.md step 5 used to read `$SECRET_VALUE` without saying how to set it. The first scripted run found the canary in shell history, and [ticket 19](../tickets/19-keep-secrets-out-of-shell-history.md) changed step 5 to `read -rs`.

`evals-offline.sh` feeds the runbook's commands to an interactive `bash -i` with Ubuntu's default `.bashrc`, so history behaves as it does for a person. Its log stands in for what the terminal shows, and the search covers it. Before it searches, it checks that the search finds each Share in its own file. It can't make the machine air-gapped: it needs the network to reach the machine.

## Results

- 2026-11-12, scratch VM, `test/e2e/evals-offline.sh`, with the step 5 that predates ticket 19: **fail**. `~/.bash_history` held `SECRET_VALUE=CANARY-…`, and the terminal showed the value too. That led to ticket 19.
- 2026-11-12, branch `evals-rest`, scratch VM, with ticket 19's step 5: **pass**. No canary, Share, key body or age identity turned up on the root file system or in the system and user journals. The history held only the `read -rs`, `printf` and `unset` lines.
