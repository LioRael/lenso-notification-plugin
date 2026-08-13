create schema if not exists notification;

create table if not exists notification.template_releases (
    id text primary key,
    template_id text not null,
    version text not null,
    locale text not null,
    renderer_identity text not null,
    template_digest text not null,
    created_at timestamptz not null,
    constraint notification_template_id_not_empty check (length(template_id) > 0),
    constraint notification_template_version_not_empty check (length(version) > 0),
    constraint notification_template_locale_not_empty check (length(locale) > 0),
    constraint notification_template_digest_format check (template_digest ~ '^sha256:[0-9a-f]{64}$'),
    unique (template_id, version, locale)
);

create table if not exists notification.render_snapshots (
    id text primary key,
    template_release_id text not null references notification.template_releases(id) on delete restrict,
    subject_ciphertext text not null,
    text_ciphertext text not null,
    html_ciphertext text not null,
    protection_key_ref text not null,
    content_digest text not null,
    redacted_preview text not null,
    created_at timestamptz not null,
    constraint notification_snapshot_ciphertexts_not_empty check (
        length(subject_ciphertext) > 0 and length(text_ciphertext) > 0 and length(html_ciphertext) > 0
    ),
    constraint notification_snapshot_digest_format check (content_digest ~ '^sha256:[0-9a-f]{64}$'),
    constraint notification_snapshot_preview_bounded check (length(redacted_preview) <= 160)
);

create table if not exists notification.intents (
    id text primary key,
    purpose text not null,
    source_module text not null,
    source_entity_type text not null,
    source_entity_id text not null,
    recipient_ciphertext text not null,
    recipient_key_ref text not null,
    recipient_mask text not null,
    locale text not null,
    snapshot_id text not null references notification.render_snapshots(id) on delete restrict,
    idempotency_key text not null,
    request_digest text not null,
    requested_by text,
    correlation_id text not null,
    causation_id text,
    requested_at timestamptz not null,
    constraint notification_intent_purpose check (purpose = 'transactional.organization_invitation'),
    constraint notification_intent_idempotency_not_empty check (length(idempotency_key) > 0),
    constraint notification_intent_request_digest_format check (request_digest ~ '^sha256:[0-9a-f]{64}$'),
    constraint notification_intent_recipient_mask_bounded check (length(recipient_mask) between 3 and 320),
    unique (source_module, idempotency_key)
);

create index if not exists notification_intents_source_idx
    on notification.intents (source_module, source_entity_type, source_entity_id);

create table if not exists notification.deliveries (
    id text primary key,
    intent_id text not null unique references notification.intents(id) on delete restrict,
    channel text not null,
    status text not null,
    revision bigint not null default 1,
    attempt_count integer not null default 0,
    max_attempts integer not null default 4,
    next_attempt_at timestamptz,
    accepted_at timestamptz,
    delivered_at timestamptz,
    final_at timestamptz,
    final_reason text,
    created_at timestamptz not null,
    updated_at timestamptz not null,
    constraint notification_delivery_channel check (channel = 'email'),
    constraint notification_delivery_status check (
        status in ('queued', 'attempting', 'accepted', 'retry_scheduled', 'delivered', 'failed', 'delivery_unknown')
    ),
    constraint notification_delivery_attempt_count check (
        attempt_count >= 0 and max_attempts between 1 and 10 and attempt_count <= max_attempts
    ),
    constraint notification_delivery_revision_positive check (revision > 0),
    constraint notification_delivery_final_consistency check (
        (status in ('delivered', 'failed', 'delivery_unknown') and final_at is not null)
        or (status not in ('delivered', 'failed', 'delivery_unknown') and final_at is null)
    )
);

create index if not exists notification_deliveries_due_idx
    on notification.deliveries (next_attempt_at, id)
    where status in ('queued', 'retry_scheduled');

create index if not exists notification_deliveries_status_updated_idx
    on notification.deliveries (status, updated_at desc, id desc);

create table if not exists notification.attempts (
    id text primary key,
    delivery_id text not null references notification.deliveries(id) on delete restrict,
    sequence integer not null,
    function_run_id text not null unique,
    dispatch_event_id text not null unique,
    status text not null,
    provider text,
    remote_receipt_id text,
    remote_receipt_source text,
    remote_receipt_digest text,
    failure_code text,
    failure_classification text,
    started_at timestamptz not null,
    completed_at timestamptz,
    constraint notification_attempt_sequence_positive check (sequence > 0),
    constraint notification_attempt_status check (
        status in ('dispatching', 'accepted', 'temporary_failure', 'permanent_failure', 'delivery_unknown')
    ),
    constraint notification_attempt_remote_digest_format check (
        remote_receipt_digest is null or remote_receipt_digest ~ '^sha256:[0-9a-f]{64}$'
    ),
    unique (delivery_id, sequence)
);

create index if not exists notification_attempts_delivery_idx
    on notification.attempts (delivery_id, sequence desc);

create table if not exists notification.receipts (
    id text primary key,
    delivery_id text not null references notification.deliveries(id) on delete restrict,
    attempt_id text not null references notification.attempts(id) on delete restrict,
    kind text not null,
    source text not null,
    remote_id text not null,
    digest text not null,
    observed_at timestamptz not null,
    recorded_at timestamptz not null,
    constraint notification_receipt_kind check (kind in ('accepted', 'delivered', 'bounced', 'rejected')),
    constraint notification_receipt_digest_format check (digest ~ '^sha256:[0-9a-f]{64}$'),
    unique (source, remote_id, kind)
);

create index if not exists notification_receipts_delivery_idx
    on notification.receipts (delivery_id, observed_at desc, id desc);

create table if not exists notification.retry_requests (
    id text primary key,
    delivery_id text not null references notification.deliveries(id) on delete restrict,
    kind text not null,
    requested_by text,
    source_revision bigint not null,
    idempotency_key text not null,
    decision text not null,
    reason text,
    scheduled_at timestamptz,
    created_at timestamptz not null,
    constraint notification_retry_kind check (kind in ('automatic', 'manual')),
    constraint notification_retry_decision check (decision in ('scheduled', 'rejected')),
    unique (delivery_id, idempotency_key)
);

create index if not exists notification_retry_requests_delivery_idx
    on notification.retry_requests (delivery_id, created_at desc, id desc);

create table if not exists notification.consumed_events (
    event_id text primary key,
    event_name text not null,
    event_digest text not null,
    consumed_at timestamptz not null,
    constraint notification_consumed_event_digest_format check (event_digest ~ '^sha256:[0-9a-f]{64}$')
);

create table if not exists notification.source_lifecycle_events (
    event_id text primary key references notification.consumed_events(event_id) on delete restrict,
    source_module text not null,
    source_entity_type text not null,
    source_entity_id text not null,
    lifecycle text not null,
    observed_at timestamptz not null,
    recorded_at timestamptz not null,
    constraint notification_source_lifecycle check (lifecycle in ('accepted', 'revoked'))
);

create index if not exists notification_source_lifecycle_entity_idx
    on notification.source_lifecycle_events (source_module, source_entity_type, source_entity_id, observed_at desc);

comment on column notification.intents.recipient_ciphertext is
    'Application-layer AEAD ciphertext. Never select from Console/API queries.';
comment on column notification.render_snapshots.subject_ciphertext is
    'Application-layer AEAD ciphertext. Never select from Console/API queries.';
comment on column notification.render_snapshots.text_ciphertext is
    'Application-layer AEAD ciphertext. Never select from Console/API queries.';
comment on column notification.render_snapshots.html_ciphertext is
    'Application-layer AEAD ciphertext. Never select from Console/API queries.';
