//! Transactional Notification intent and source-lifecycle role.

#[allow(unknown_lints)]
#[allow(
    clippy::chunks_exact_to_as_chunks,
    clippy::manual_div_ceil,
    clippy::manual_is_multiple_of,
    clippy::verbose_bit_mask
)]
mod generated {
    include!("generated.rs");
}

pub use generated::*;

/// Source request Schema used by conformance and package-boundary tests.
pub const CREATE_ORGANIZATION_INVITATION_REQUEST_SCHEMA_JSON: &str =
    include_str!("../schemas/create-organization-invitation-request.schema.json");

/// Source request Schema used by conformance and package-boundary tests.
pub const CREATE_ACCESS_REQUEST_NOTIFICATION_REQUEST_SCHEMA_JSON: &str =
    include_str!("../schemas/create-access-request-notification-request.schema.json");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn access_request_recipient_is_redacted_from_debug() {
        let request = CreateAccessRequestNotificationRequest {
            causation_id: None,
            correlation_id: "corr_1".to_owned(),
            event: CreateAccessRequestNotificationRequestEvent::Submitted,
            expires_at: Some("2026-09-01T00:00:00Z".to_owned()),
            idempotency_key: "access-request:ar_1:submitted".to_owned(),
            organization_id: "org_1".to_owned(),
            recipient: CreateAccessRequestNotificationRequestRecipient {
                address: "private@example.com".to_owned(),
                display_name: Some("Private Person".to_owned()),
                locale: CreateAccessRequestNotificationRequestRecipientLocale::En,
            },
            request_id: "ar_1".to_owned(),
            requested_by: Some("subject_1".to_owned()),
            role: CreateAccessRequestNotificationRequestRole {
                display_name: Some("Member".to_owned()),
                role_id: "role_member".to_owned(),
            },
            scope: CreateAccessRequestNotificationRequestScope {
                display_name: Some("Acme".to_owned()),
                id: "org_1".to_owned(),
                kind: "organization".to_owned(),
            },
        };
        let debug = format!("{request:?}");
        assert!(!debug.contains("private@example.com"));
        assert!(!debug.contains("Private Person"));
        assert!(debug.contains("<redacted>"));
    }
}
