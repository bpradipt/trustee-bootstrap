# EV-05: Security Operator reviews a weakened Init-Data

**Category:** operator mistake
**Runs on:** genpolicy and the test registry, no CVM; `test/e2e/evals-cluster.sh ev05`
**Covers:** residual risk "Init-Data is the single root"; conditions 2 and 4; [unlock-ceremony.md](../runbooks/unlock-ceremony.md) part 2, step 1

## Setup

Render `trustee-cvm.yaml` and extract `init.toml` as the Unlock Ceremony runbook's part 1 says, steps 1 to 5. Then make one weakened copy per row, run genpolicy on it, and extract its `init.toml`:

| Variant | Change before genpolicy |
|---|---|
| tag | The helper image by tag, not by digest |
| manifest | `--manifest-sha256` of another Key Ceremony's manifest |
| owner | `--owner-uid=1000` |
| exec | genpolicy settings that allow `ExecProcessRequest` |
| logs | genpolicy settings that allow `ReadStreamRequest` |
| kbs-url | The KBS URL in `aa.toml` and `cdh.toml` points off the guest loopback |
| sidecar | An extra container in the pod |
| kbs-image | A KBS image digest other than the one in `docs/upstream-pins.md` |

## Action

A Security Operator who doesn't know which variant they hold runs part 2, step 1 on each `init.toml`, including the unchanged one. An agent can run it: the step is a list of commands, plus reading `policy.rego`.

## Expected

- The unchanged `init.toml` passes every check.
- Each weakened copy fails at least one check, and the Security Operator stops before `policy build`. Record which check caught it.

A variant that passes the whole checklist fails the eval. Add a check to the runbook for it.

## Notes

The checklist has no line for the number of containers. The sidecar variant shows whether reading `policy.rego` catches what the greps miss.

## Results

- 2026-11-12, branch `evals-rest`, scratch VM (kind + Kata 4.2.0 + swtpm), `test/e2e/evals-cluster.sh`: **fail**. The checklist caught seven of the eight variants but not the sidecar, which led to [ticket 22](../tickets/22-review-the-container-set.md).
- 2026-11-12, branch `evals-rest`, scratch VM (kind + Kata 4.2.0 + swtpm), `test/e2e/evals-cluster.sh`, with ticket 22's container-set check: **pass**. The unchanged Init-Data passed every check, and every variant failed at least one. The sidecar failed the container set, and the KBS image failed the KBS digest.
