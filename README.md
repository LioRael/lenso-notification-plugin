# Lenso Notification Plugin

This repository owns removable, PostgreSQL-backed transactional Notification
behavior for Lenso applications. Supported purposes are
`organization-invitation@v1` and the four bounded
`access-request-{submitted,approved,denied,expiring}@v1` lifecycle messages.
SMS, push, campaigns, arbitrary-send operations, credential editing, and visual
template editing remain outside the boundary.

The workspace contains four portable Capability Contracts and one native
implementation:

- `lenso.notification.transactional@1` creates invitation intent, creates
  bounded access-request lifecycle intent, and records invitation source
  lifecycle observations.
- `lenso.notification.delivery@1` claims due work and records authoritative
  delivery receipts.
- `lenso.notification.admin@1` reads the redacted ledger and requests an
  explicit manual retry.
- `lenso.notification-template@1` is the required external immutable-template
  and safe-rendering role.
- `lenso.email-dispatch@1` is the required external email-effect role.
- `lenso-notification-plugin` provides the three Notification roles as Plugin
  `lenso.notification` in root Slot `notifications`.

Generated Clients and Providers are the only public business call surface.
Binding a Capability is necessary but not sufficient authority: immutable
configuration allowlists exact caller Instance keys for transactional,
dispatch, authoritative receipt, and admin operations independently. Source identity is always derived from the
Kernel-authenticated caller; request payloads cannot claim another Plugin.

## Delivery and storage

Notification owns its PostgreSQL schema, business attempts, receipts, and
retry decisions. Claiming a delivery appends the attempt before invoking the
exact bound `lenso.email-dispatch@1` Provider. SMTP or provider acceptance is
`accepted`, never `delivered`; only an authoritative receipt produces
`delivered`. A Runtime failure or invalid Provider response after invocation is
recorded as terminal `delivery_unknown` and is never retried automatically.

The invitation source may observe `accepted`, `revoked`, or `expired`; each
caller-scoped, idempotent observation cancels only still-queued or scheduled
work for that source invitation.

Access-request notification input contains only a request/Organization id,
recipient, event, bounded role/scope display fields, optional expiry, and
correlation metadata. There is no arbitrary subject, HTML, template, reason,
or approval-note field. Notification requests the exact built-in `v1` release
from its bound `lenso.notification-template@1` Provider, validates the returned
identity and content digest, and persists that immutable render as its protected
delivery snapshot. The exact key
`access-request:<request_id>:<event>` is required, so the same caller and
request/event pair deduplicates while changed input conflicts. A successful
call means only that durable intent was accepted; it never claims delivery.

Exact idempotent replays are read from the Notification ledger before a render
call, so an already accepted intent remains replayable if the Template Provider
is temporarily unavailable. New intent creation fails without any Notification
write when rendering fails. In App Composition, bind exactly one Template
Provider and include the Notification Plugin's selected Instance key in that
Provider's `render_callers`; this is a service-to-service authority, not a
forwarded business caller identity.

Schema lifecycle is operator-owned:

```rust
use notification::NotificationOperator;

NotificationOperator::setup(&database_url).await?;
NotificationOperator::upgrade(&database_url).await?;
```

Plugin `prepare` resolves the database URL and 32-byte base64 snapshot key via
`lenso.secrets@1`, then only validates the already-managed `notification`
schema: both the migration ledger and the complete managed catalog fingerprint.
It never runs setup or upgrade. Existing v0.3 installations first call
`NotificationOperator::adopt_legacy`; that explicit, fail-closed operation
requires the exact legacy Host migration-ledger evidence, builds a same-server
temporary reference from the unchanged v1 SQL, and accepts only a catalog match
including ownership, object/default ACLs, comments, relation attributes,
columns/defaults, constraints, indexes, types, routines, policies, inheritance,
rules, security labels, and publication membership. It never runs the reference
SQL against `notification` and preserves all rows. Adoption is a one-time
maintenance-window operation: it takes a shared lock on the legacy Host ledger
and access-exclusive locks on all nine legacy Notification tables until commit,
so reads and writes to those tables may block for the duration. Operators must
stop all Notification writers and DDL actors: adoption first takes the shared
database `:lenso-maintenance` advisory key used by cooperating schema operators,
then the Notification-specific key. These advisory locks do not coordinate
direct owner DDL, and the table locks do not prevent an arbitrary same-role
`CREATE TABLE` or `CREATE FUNCTION` in the schema namespace. Every
subsequent Plugin `prepare` repeats the full managed fingerprint and rejects
objects that slipped into adoption or were added later.

Legacy adoption records the proven immutable v1 schema only. Operators then
run `NotificationOperator::upgrade` before selecting a Plugin version whose
schema plan includes later migrations, including the `expired` invitation
lifecycle constraint and the bounded access-request purpose.

## vNext compatibility boundary

This is a deliberate breaking migration. The old `lenso-module-notification`
package, `HostLinkedModule`, shared transaction API, Host Outbox, Runtime
function, Event subscription, generated module manifest, and Console manifest
hook are not retained as compatibility shims. Applications on the v0.3 lane,
including the current invitation example, must remain on their historical
dependency until they select this Plugin and call generated Capability Clients.

The existing `lenso-email-provider-service` is also on the legacy lane. A
deployable composition requires an email Plugin that implements
`lenso.email-dispatch@1` and a Template Plugin that implements
`lenso.notification-template@1`; repository test Providers prove generated
boundaries but are not production implementations.

That email contract treats `invalid_dispatch` and `unsupported_message` as
pre-effect Domain rejections only. Once an external effect starts, the Provider
must report uncertainty as response `delivery_unknown` or Runtime failure;
Notification terminalizes Runtime and invalid protocol results as
`delivery_unknown` and does not retry them.

The Admin wire projection is deliberately bounded: list pages contain at most
200 deliveries, one detail response contains at most 10 attempts and 1,000 each
of receipts and retry decisions, and revisions stay within the portable
JavaScript-safe integer range. Detail queries fetch one row beyond each evidence
limit and return `evidence_overflow` rather than silently truncating history.

## Console artifact

`packages/notification-console` is retained as a static, buildable UI artifact.
It is not an App-reachable Surface in this migration. A separate Web/Console
Adapter must require `lenso.notification.admin@1` and publish the supported
`lenso.http.endpoint@1` boundary before the UI can be selected.

The current `lenso-web` endpoint authoring revision still resolves older Lenso
core/runtime/protocol source revisions than this Plugin. Importing it here
would create duplicate Kernel types, so this repository deliberately contains
no HTTP Adapter, path patch, or legacy Host shim. The prerequisite is dependency
alignment in `lenso-web`, followed by a separately removable Adapter Plugin.

See [the Plugin card](docs/plugin-card.md) and
[the domain boundary](docs/domain/notification.md).

## Development

```sh
cargo fmt --all -- --check
cargo check --locked --workspace --all-targets
cargo test --locked --workspace
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
pnpm install --frozen-lockfile
pnpm check
./scripts/check-public-packages.sh
```

The PostgreSQL acceptance uses `LENSO_TEST_DATABASE_URL` and refuses destructive
setup unless `current_database()` is exactly `notification_test` or starts with
`notification_test_`. Local runs without the variable skip that test; CI always
provides a dedicated PostgreSQL 18 service and fails if the URL is absent.
