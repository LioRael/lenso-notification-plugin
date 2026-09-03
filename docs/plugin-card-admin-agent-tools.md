# Notification Admin Agent Tools Plugin card

## Owner and deletion boundary

`lenso-notification-admin-agent-tools-plugin` is a private, stateless adapter.
Removing it removes only the Console Agent's Notification administration Tools.
Deliveries, rendered snapshots, attempts, receipts, retry decisions, status,
revision, encryption, and PostgreSQL lifecycle remain owned by Notification.

## Roles

- Provides `lenso.agent.tool-provider@2` in the `tool-providers` root slot.
- Requires exactly one `lenso.notification.admin@1` provider.
- Exposes `notification_admin_list_deliveries` and
  `notification_admin_get_delivery` as parallel-safe reads.
- Exposes `notification_admin_retry_delivery` as an exclusive mutation.

## Authority and sensitive-data boundary

The adapter reuses the existing portable request schemas and forwards the
invocation context unchanged. Notification retains exact admin-caller
admission, redaction, evidence limits, current revision checks, idempotency,
retry eligibility, and every durable state transition.

Only recipient masks, redacted previews, content digests, statuses, and bounded
evidence metadata can be returned. The adapter does not expose recipient
addresses, rendered message bodies, invitation URLs, provider transcripts,
credentials, transactional intent, delivery-worker operations, templates, or
email dispatch.
