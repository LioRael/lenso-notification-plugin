# Notification Plugin card

## Owner and deletion boundary

`lenso.notification` owns transactional invitation and access-request lifecycle
intent, immutable protected render snapshots, delivery state, append-only
attempts, authoritative receipts, source lifecycle observations, and retry
decisions. Removing the Plugin from
App Composition removes all three provided Capability endpoints and stops new
dispatch work. It requires no Kernel branch and does not delete the existing
PostgreSQL schema or evidence rows; data retention or erasure is a separate,
explicit operator workflow.

The caller's business Plugin remains authority for its own invitation. The
Notification Plugin derives source identity from the Kernel-authenticated caller
Instance and checks an immutable role allowlist. It never trusts a payload field
to name a source Plugin or receipt Provider.

## Contract and implementation

- Plugin ID: `lenso.notification`; root Slot: `notifications`.
- Provided request Capabilities: `lenso.notification.transactional@1`,
  `lenso.notification.delivery@1`, and `lenso.notification.admin@1`, all at
  descriptor `1.1.0` for Transactional and `1.0.0` for Delivery/Admin,
  portable, and cross-lane transferable.
- Required Capabilities: exactly one `lenso.secrets@1` Provider, exactly one
  `lenso.email-dispatch@1` Provider, and exactly one
  `lenso.notification-template@1` descriptor `1.0.0` Provider.
- Implementation: linked native Rust with a Plugin-owned PostgreSQL schema and
  generated Client/Provider glue.
- Configuration: fixed schema identity; database and snapshot-key Secret
  references; exact transactional, dispatch scheduler, authoritative receipt
  observer, and admin caller Instance lists.
  Production performs no environment discovery.
- Generation state: one verified PostgreSQL pool and one AEAD snapshot protector
  per prepared Plugin generation. Deactivation closes the pool.

`lenso.email-dispatch@1` is an external effect role. The current legacy
`lenso-email-provider-service` does not yet implement it; the test Provider in
this repository proves generated composition only and must not be selected in a
production App. Its Domain errors are strictly pre-effect rejections. Once an
effect starts, uncertainty is response `delivery_unknown` or Runtime failure,
both of which Notification handles without replaying the effect.

`lenso.notification-template@1` owns immutable template definitions, locale
fallback, and safe rendering. Notification always requests an explicit `v1`
for its five typed template ids, validates Provider metadata and digests, and
stores the resolved template locale with the protected snapshot. The Template
Provider must allow the selected Notification Instance key in `render_callers`.
Exact committed replays do not depend on Provider availability; a failed render
for a new intent writes nothing.

## Observable behavior

The vertical workflow is intent -> protected snapshot -> queued delivery ->
append attempt -> email dispatch -> known result or `delivery_unknown` ->
authoritative receipt. Provider acceptance is observable as `accepted`, never
as delivery. `delivery_unknown` remains terminal because replay could duplicate
an external effect.

Source invitation observations cover `accepted`, `revoked`, and `expired`.
They are caller-scoped and idempotent and terminalize only queued or
retry-scheduled work that existed before the observation.

`create_access_request_notification` accepts only submitted, approved, denied,
or expiring events and fixed bounded role/scope display data. It exposes no
arbitrary template/HTML and accepts no access reason or approval note. The
request/event-derived idempotency key is
mandatory: exact replay returns the existing intent, while any changed input
conflicts. Acceptance means the durable delivery ledger contains the intent;
it is not evidence that email was delivered.

Durable cadence is not hidden inside Kernel Event fanout or a generic worker.
An App selects a Jobs/Scheduler/Workflow owner that explicitly calls
`dispatch_due`; Notification retains the atomic claim and business retry policy.

Admin responses are bounded Capability values, not an unbounded ledger dump.
List pages are capped at 200 records; a delivery detail is capped at 10 attempts
and 1,000 receipts and retry decisions. The repository probes each evidence
collection with `limit + 1` and returns `evidence_overflow` instead of truncating
append-only evidence. All exposed revisions use the JavaScript-safe integer
range.

## Operator boundary

`NotificationOperator::setup` and `upgrade` own schema mutation. Runtime
`prepare` only resolves Secrets and verifies both the current migration ledger
and exact managed catalog fingerprint. Existing
v0.3 schemas use the explicit `adopt_legacy` path. It requires the exact legacy
Host row `notification/0001_create_notification_schema` in a correctly owned,
unshared `platform.schema_migrations` ledger. It then projects the compiled,
unchanged v1 SQL into the connection-local temporary schema and compares schema
and table owners, ACLs, columns/defaults/identity/generated attributes, comments,
relation persistence/access method/options/partitioning, all constraints and
indexes, user triggers, types, routines, policies, inheritance, non-view rules,
security labels, publication membership, and relevant default privileges
against the target catalog. Only an exact match records the Plugin-owned v1
checksum, and the new ledger is rechecked as private before commit. The
reference SQL is never run against `notification`, and adoption never rewrites
business rows or silently claims a coincidentally similar schema.

Adoption is a one-time maintenance-window operation. In the same transaction it
takes `SHARE` on `platform.schema_migrations` and `ACCESS EXCLUSIVE` on the nine
legacy Notification tables, in a fixed order, before reading provenance and
catalog fingerprints. Operators must expect reads and writes against those
tables to block until adoption commits or rolls back, and must stop all
Notification writers and DDL actors. Before schema-specific locking, adoption
takes the database-wide `:lenso-maintenance` advisory key shared by cooperating
schema operators, then the Notification operator key. Direct owner DDL does not
participate in that protocol; neither advisory key nor the table locks is a
general schema namespace lock, so arbitrary same-role `CREATE TABLE` or `CREATE
FUNCTION` is not atomic with adoption. The full managed fingerprint at every
later `prepare` rejects any object that slipped through or was added after
adoption.

Adoption records the exact legacy v1 migration. The operator must run
`NotificationOperator::upgrade` afterward so later forward-only migrations are
present before Plugin preparation.

## Console and Web boundary

`packages/notification-console` is a retained static UI build, not a currently
selectable or reachable App Surface. It has no HTTP endpoint in this Plugin.
The future Adapter must be a separate removable Plugin that requires
`lenso.notification.admin@1` and provides `lenso.http.endpoint@1`.

That Adapter is currently blocked: `lenso-web` revision `d4943b1` still resolves
core `cd35675`, runtime `b763a63`, and protocols `9769bc`, while this Plugin uses
core `8599db7`, runtime `8981510`, and protocols `9d2774c`. Importing it would
create duplicate Kernel/source types. This migration therefore adds no path
patch, dependency downgrade, Host shim, or fake endpoint.

The private `lenso.notification.admin.agent-tools` adapter is separately
removable and independent of that HTTP prerequisite. It exposes the Admin
role's two redacted reads and revision-checked manual retry, forwards the
invocation context, and leaves exact caller admission and all retry decisions
with Notification. It does not expose transactional, delivery-worker,
template, or email operations.

## vNext break

The legacy `lenso-module-notification` package and its linked transaction,
Host Outbox/Runtime/Event, module manifest, and Console hook are removed. Git
history is the compatibility record. Legacy consumers must migrate their App
Plan and use generated Capability Clients; this repository does not ship a
dual-lane adapter.
