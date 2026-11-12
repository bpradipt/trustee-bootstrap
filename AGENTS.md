## Agent skills

### Issue tracker

Tickets live as Markdown files in `docs/tickets/`, with a status table in `docs/tickets/README.md`. See `docs/agents/issue-tracker.md`.

### Domain docs

Single-context: one `GLOSSARY.md` and `docs/adr/` at the repo root. See `docs/agents/domain.md`.

## Working rules

- **Commits:** sign off every commit with `git commit -s`. Write the message with the `commit-messages` skill.
- **Prose:** run docs, ADRs, the spec, the glossary, commit bodies and PR text through the `stop-slop` skill.
- **Go code:** load the Go skills through `cc-skills-golang:golang-how-to` before you write or review Go.
- **Before each commit that touches Go:** run `test/e2e/ci.sh go` and `test/e2e/ci.sh lint <base>` from the repo root, and commit only when both exit `0`.
