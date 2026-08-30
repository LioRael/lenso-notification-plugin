# Email Dispatch Capability

`lenso.email-dispatch@1` is the explicit external-effect boundary used by the
Notification Plugin. A Provider owns provider credentials, transport calls,
and provider-specific evidence; Notification owns intent, attempt, receipt,
retry, and terminal-state policy.

The `invalid_dispatch` and `unsupported_message` Domain errors are
**pre-effect rejections**. A Provider may return either error only before it has
started any external effect. After an external effect starts, an uncertain
result must be returned as a successful response whose outcome is
`delivery_unknown`, or as a Runtime failure when no trustworthy response can be
formed. Notification treats Runtime and invalid protocol responses after
invocation as terminal `delivery_unknown`; it never silently retries them.

Native Providers must validate every request field against the JSON Schema
bounds before starting an external effect. Native Clients receive typed Rust
values but do not gain implicit JSON Schema min/max validation. Providers must
also produce the response cross-field shape declared by the response schema:
only `accepted` may include a remote receipt, only failure outcomes include
failure metadata, classification must match the outcome, and retry delay is
allowed only for `temporary_failure`.

The existing `lenso-email-provider-service` is still a legacy implementation
and does not yet provide this Capability. Repository-local fixtures are
contract evidence only, not a production email Provider.
