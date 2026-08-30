# Changelog

## Unreleased

### Features

- Migrate the transactional Notification ledger to removable Plugin
  `lenso.notification` with generated Transactional, Delivery, Admin, and
  Email Dispatch Capability roles.
- Preserve protected immutable snapshots and append-only attempts, receipts,
  and retry decisions while replacing Host Outbox/Runtime integration with a
  Plugin-owned PostgreSQL transaction and an explicit Email Dispatch Provider.
- Add fail-closed operator adoption for the exact legacy schema. The retained
  Deliveries Console build now requires a future independent HTTP Adapter.
