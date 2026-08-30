# Changelog

## Unreleased

### Features

- Extend `lenso.notification.transactional@1` additively to descriptor 1.1.0
  with deterministic, bounded submitted/approved/denied/expiring access-request
  notifications and request/event-stable idempotency.
- Migrate the transactional Notification ledger to removable Plugin
  `lenso.notification` with generated Transactional, Delivery, Admin, and
  Email Dispatch Capability roles.
- Preserve protected immutable snapshots and append-only attempts, receipts,
  and retry decisions while replacing Host Outbox/Runtime integration with a
  Plugin-owned PostgreSQL transaction and an explicit Email Dispatch Provider.
- Add fail-closed operator adoption for the exact legacy schema. The retained
  Deliveries Console build now requires a future independent HTTP Adapter.
