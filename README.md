# Lenso Notification Module

Linked Rust Module and release-bound Console Surface for transactional email
notification intent, immutable rendering, attempts, receipts, retry decisions,
and final status.

The first supported purpose is `organization-invitation@v1`. SMS, Push,
campaigns, arbitrary-send endpoints, credential editing, and visual template
editing are deliberately absent.

## Authoring dependency

This Module uses the public Linked Event/Runtime authoring facade shipped in
`lenso 0.3.44` through the `host` feature. It builds from the published crate
without sibling checkout patches. No `lenso-platform-*` crate is a direct
dependency.

## Checks

```sh
cargo test --workspace
pnpm install
pnpm generate:console-manifest
pnpm check
pnpm build:release-receipt
EMAIL_PROVIDER_SERVICE_ROOT=/path/to/lenso-email-provider-service pnpm check:ecosystem
```

See [the domain boundary](docs/domain/notification.md) and the templates in
`release/` for immutable Module Release and Surface API Grant binding.
