# Issue tracker: Local Markdown

Tickets for this repo live as Markdown files in `docs/tickets/`. The spec they implement is `IMPLEMENTATION_SPEC.md` at the repo root.

## Conventions

- One file per ticket at `docs/tickets/<NN>-<slug>.md`, numbered from `01`, never a single combined tickets file
- `docs/tickets/README.md` points to the spec and keeps a status table of every ticket; update the table when a ticket's status changes
- Triage state is recorded as a `Status:` line near the top of each ticket file
- Comments and conversation history append to the bottom of the file under a `## Comments` heading
- A second feature gets its own directory, `docs/tickets/<feature-slug>/`, with the same layout

## When a skill says "publish to the issue tracker"

Create a new file under `docs/tickets/` and add it to the status table in `docs/tickets/README.md`.

## When a skill says "fetch the relevant ticket"

Read the file at the referenced path. The user will normally pass the path or the ticket number directly.

## Wayfinding operations

Used by `/wayfinder`. The **map** is a file with one **child** file per ticket.

- **Map**: `docs/tickets/<effort>/map.md` (the Notes / Decisions-so-far / Fog body).
- **Child ticket**: `docs/tickets/<effort>/<NN>-<slug>.md`, numbered from `01`, with the question in the body. A `Type:` line records the ticket type (`research`/`prototype`/`grilling`/`task`); a `Status:` line records `claimed`/`resolved`.
- **Blocking**: a `Blocked by: NN, NN` line near the top. A ticket is unblocked when every file it lists is `resolved`.
- **Frontier**: scan `docs/tickets/<effort>/` for files that are open, unblocked, and unclaimed; first by number wins.
- **Claim**: set `Status: claimed` and save before any work.
- **Resolve**: append the answer under an `## Answer` heading, set `Status: resolved`, then append a context pointer (gist + link) to the map's Decisions-so-far in `map.md`.
