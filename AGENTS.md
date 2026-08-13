# Agent instructions

Before planning, changing, or executing a release, read this repository's
`.github/workflows/release-plz.yml`. Do not infer production authority from
repository write access. Registry publication, immutable tags, and GitHub
Releases require the repository's Trusted Publisher workflow and explicit
approval.

Notification is a linked Lenso Module. Keep business state, retry policy, and
the operator Surface in this repository. Email transport credentials and
provider calls belong to the Email Provider Service.

- Use only the public `lenso` facade; do not depend on `lenso-platform-*` crates.
- Keep migrations forward-only and preserve append-only attempts and receipts.
- Never expose recipient addresses, rendered message bodies, invitation URLs,
  provider transcripts, credentials, or secret material through Console APIs.
- SMTP acceptance is not delivery. Ambiguous external effects become
  `delivery_unknown` and are never retried automatically.

## Agent skills

Issues and PRDs are tracked in the central `LioRael/lenso` repository. See
`docs/agents/issue-tracker.md`, `docs/agents/triage-labels.md`, and
`docs/agents/domain.md`.
