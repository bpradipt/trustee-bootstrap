# EV-08: Ceremonies leave no secret on disk

**Category:** operator mistake
**Runs on:** the scratch VM, playing the Key Ceremony machine and then the sealing machine
**Covers:** residual risk "the Infrastructure Operator sees the plaintext config"; condition 7; asset requirements for the bootstrap private key and the plaintext config; [key-ceremony.md](../runbooks/key-ceremony.md); [seal.md](../runbooks/seal.md); ADR 0008

## Setup

- A fresh VM with swap off, the release binaries and the tools both runbooks list.
- A canary resource secret, `CANARY-<32 random hex>`.
- A checker shell that holds every search string in memory only: the canary, and each Share string, read from the tmpfs before the runbook unmounts it.

## Action

1. Walk key-ceremony.md steps 1 to 7 as a person would, in an interactive shell. Skip the `poweroff`.
2. Walk seal.md steps 1 to 8. Set `SECRET_VALUE` to the canary the way an Infrastructure Operator would, typing it at the prompt.
3. From the checker shell, search for each string and for `AGE-SECRET-KEY-1`, `BEGIN EC PRIVATE KEY` and `BEGIN PRIVATE KEY` in:
   - every file system except `/proc`, `/sys` and `/dev`;
   - the shell history files;
   - `/tmp` and `~/.cache`;
   - `journalctl`, system and user.

## Expected

- No search finds a match.
- Every witness check in both runbooks passes.

## Notes

seal.md step 5 reads `$SECRET_VALUE` but doesn't say how to set it. If the eval finds the canary in shell history, the runbook needs a step that reads the value without echoing it, such as `read -rs SECRET_VALUE`.

## Results

None yet.
