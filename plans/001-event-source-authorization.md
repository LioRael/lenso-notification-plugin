# Plan 001: Authorize every consumed Event source before state mutation

> Drift check: `git diff --stat b001dff..HEAD -- crates/notification/src/events.rs crates/notification/src/plugin.rs`.

## Status

- **Priority**: P1
- **Effort**: S
- **Risk**: MED
- **Depends on**: none
- **Category**: security
- **Planned at**: commit `041335a`, 2026-08-30

## Why this matters

Notification observations mutate durable delivery state. Their producer identity must
come from the generated Capability invocation context or the selected Email Provider,
and a forged private envelope must fail before opening a database transaction.

## Current state

- Generated Capability handlers derive the caller from `InvocationContext` and check
  operation-specific allowlists before constructing an `ObservationEnvelope`.
- Dispatch observations are internal results from the exactly selected Email Provider.
- `events.rs` still needs to bind the private envelope source to the decoded dispatch
  provider or receipt source before any state mutation.
- Follow the existing `NotificationError(ErrorCode::Validation)` rejection convention.

## Scope

In scope: the private observation seam, operation-specific caller authorization, and
focused source-forgery tests. Out of scope: changing Capability contracts or adding a
second caller-selected source field.

## Steps

1. Preserve the plugin-first trust boundary: derive source from the authorized caller
   or selected Email Provider rather than request payload.
2. Reject blank, oversized, or payload-mismatched private envelope sources before
   beginning a transaction.
3. Cover forged dispatch/receipt sources and an unauthorized invitation lifecycle
   caller without requiring a live database.

## Verification

- `lenso-cargo test --locked -p lenso-notification-plugin` -> all pass.
- `pnpm check` -> exit 0.
- `git diff --check` -> no output.

## STOP conditions

Stop if a source must be accepted from request payload rather than invocation context
or the selected dependency; report the trust-boundary ambiguity instead.
