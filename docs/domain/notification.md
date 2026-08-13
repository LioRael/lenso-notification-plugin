# Notification domain

Notification owns the business ledger for one transactional email lifecycle.
It does not own SMTP credentials, provider accounts, raw transcripts, Host
Runtime records, SMS, Push, campaigns, or template editing.

## First workflow

1. Organization creates an invitation and calls
   `notification::public::create_transactional_email_intent_in_tx` using the
   same caller-owned `LinkedTransaction`.
   The integration identity is the actual linked Module manifest name
   `organization` (not the canonical release id `lenso/organization`).
2. Notification pins `organization-invitation@v1`, protects recipient and
   rendered subject/text/HTML, and creates one queued delivery.
3. `notification.dispatch-due.v1` atomically appends a business attempt and
   publishes `lenso.email.dispatch-requested.v1` through the Host Outbox.
4. Email Provider Service records the transport effect and emits a known
   dispatch outcome. SMTP `250` is `accepted`, never `delivered`.
5. Authoritative provider receipt evidence is the only path to `delivered`.
   Ambiguous effects become `delivery_unknown` and are closed to automatic and
   manual retry.

## Identities and retry

- One intent key plus one request digest is a business idempotency claim.
- One Notification attempt has one stable `function_run_id`.
- Provider invocation sub-attempts remain Host/Provider technical evidence.
- A known temporary result closes the current attempt and schedules a new
  Notification attempt. It is not hidden as a Host technical retry.
- Attempts, receipts, and retry decisions are append-only.

## Sensitive content boundary

`notification.intents.recipient_ciphertext` and the three ciphertext columns
in `notification.render_snapshots` use authenticated application-layer
envelopes. Production fails closed without a 32-byte base64 secret supplied as
`LENSO_NOTIFICATION_SNAPSHOT_KEY`; the Manifest declares the corresponding
secret reference. The Console queries never select these columns. They expose
only a recipient mask, independently rendered redacted preview, and digest.

The dispatch Outbox payload necessarily contains delivery plaintext while it
crosses the Provider boundary. It is marked `log_payload=false`; Host and Email
Service must apply restricted access and short retention. Credentials and raw
provider transcripts never enter Notification Events.
