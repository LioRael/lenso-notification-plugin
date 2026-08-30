# Notification domain

Notification owns one durable business ledger for transactional email intent,
immutable rendered snapshots, delivery attempts, receipts, retry decisions,
and final status. It does not own template definitions or rendering policy,
SMTP credentials, provider accounts, raw provider transcripts, Kernel execution
records, SMS, push, campaigns, or template editing.

## Transactional workflows

1. An authorized business Plugin calls the exact generated invitation or
   access-request operation on `lenso.notification.transactional@1`. The caller
   Instance, not a payload field, becomes the source identity and idempotency
   scope.
2. For a new intent, Notification calls the exact bound
   `lenso.notification-template@1/render` operation with a fixed template id,
   explicit `v1`, locale, and typed variable set. It validates the returned
   template/version/locale metadata and recomputes the content digest before it
   protects subject/text/HTML and commits one queued delivery in its own
   transaction.
3. An authorized worker calls `lenso.notification.delivery@1/dispatch_due`.
   Notification atomically appends one immutable attempt before invoking the
   exact bound `lenso.email-dispatch@1` Provider.
4. A known temporary outcome schedules a new business attempt. A known
   permanent rejection closes the delivery. An ambiguous Runtime or protocol
   result becomes `delivery_unknown`.
5. Provider acceptance remains `accepted`; only an authorized receipt call
   derived from the caller Provider Instance can produce `delivered`.

Invitation sources may observe `accepted`, `revoked`, or `expired`. Each state
terminalizes only queued or retry-scheduled delivery work that predates the
observation; source identity remains caller-derived and the observation is
idempotent.

Access-request lifecycle intent is limited to submitted, approved, denied, and
expiring. Role/scope data is display-only and bounded. The Capability has no
arbitrary HTML/template field and no reason or approval-note field. Rendering
is delegated only to the typed Template Capability; Notification never accepts
caller-supplied markup. The mandatory
`access-request:<request_id>:<event>` key makes one caller's request/event pair
idempotent; changed input conflicts. Intent acceptance is not delivery proof.

The generated request Capability is used because durable success and
Domain/Runtime failure classification matter. Kernel Event fanout is volatile
and is not a delivery ledger, scheduler, or substitute for these transactions.
Historical-looking observation names retained inside the private ledger are
idempotency/evidence labels only; they are not published Kernel Event Contracts
or an active transport surface.

Email Dispatch Domain errors (`invalid_dispatch` and `unsupported_message`) are
valid only before the Provider starts an external effect. After that boundary,
an uncertain Provider result is response `delivery_unknown` or Runtime failure.
Notification rejects inconsistent native response shapes and terminalizes them
as `delivery_unknown`; it never converts an invalid retry delay into a retry.

## Idempotency and retry

- One caller Instance plus one intent idempotency key and request digest is the
  business idempotency claim.
- A committed exact replay is returned before a Template Provider call. A new
  intent is rendered before opening its write transaction and is rechecked
  under the existing advisory lock, preserving concurrent CAS semantics.
- One Notification attempt has one stable run ID and one provider idempotency
  key.
- Known temporary outcomes close the current attempt before scheduling another.
- Attempts, receipts, source observations, and retry decisions are append-only.
- `delivery_unknown` is terminal and closed to automatic and manual retry.
- Manual retry requires a current delivery revision and a separate idempotency
  key; it never edits or deletes prior evidence.

## Sensitive content

Recipient and rendered message columns use authenticated application-layer
envelopes. Production preparation fails closed unless the configured Secret
resolves to exactly 32 base64-decoded bytes. Generated email-dispatch request
types redact recipient and body fields from `Debug` output.

Admin Capability queries never select ciphertext. They expose only a recipient
mask, independently rendered redacted preview, content digest, statuses, and
append-only evidence metadata. Credentials and raw provider transcripts never
enter Notification state.

## Operator and adapter boundaries

The Plugin owns the fixed `notification` schema. `prepare` validates the exact
operator-managed migration ledger and complete managed catalog fingerprint;
setup, upgrade, and one-time exact legacy
adoption are explicit `NotificationOperator` actions. Adoption requires a
maintenance window because it locks the legacy Host ledger and all nine legacy
Notification tables while it proves provenance and exact catalog shape. Those
locks do not serialize arbitrary schema-local `CREATE` statements, so all DDL
actors must also be stopped; a later `prepare` rejects any slipped or post-
adoption catalog object.
Historical migration SQL is immutable. Adoption records v1, then the explicit
operator upgrade applies later forward-only migrations before runtime prepare.

The retained Console source is not a reachable Surface. A future independent
Adapter must require `lenso.notification.admin@1` and publish
`lenso.http.endpoint@1` after `lenso-web` aligns to this repository's Lenso
dependency baseline. It must not access Notification tables or restore Host
HTTP/admin hooks.
