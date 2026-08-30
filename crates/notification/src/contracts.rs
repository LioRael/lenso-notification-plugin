use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub const EMAIL_DISPATCH_OBSERVED_EVENT: &str = "lenso.email.dispatch-observed.v1";
pub const EMAIL_RECEIPT_OBSERVED_EVENT: &str = "lenso.email.receipt-observed.v1";
pub const ORGANIZATION_INVITATION_ACCEPTED_EVENT: &str =
    "lenso.organization.invitation-accepted.v1";
pub const ORGANIZATION_INVITATION_EXPIRED_EVENT: &str = "lenso.organization.invitation-expired.v1";
pub const ORGANIZATION_INVITATION_REVOKED_EVENT: &str = "lenso.organization.invitation-revoked.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DispatchOutcome {
    Accepted,
    TemporaryFailure,
    PermanentFailure,
    DeliveryUnknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RemoteReceiptSummary {
    pub remote_id: String,
    pub source: String,
    pub digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SanitizedFailure {
    pub code: String,
    pub classification: String,
    pub retry_after_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EmailDispatchObserved {
    pub delivery_id: String,
    pub attempt_id: String,
    pub function_run_id: String,
    pub outcome: DispatchOutcome,
    pub provider: String,
    pub observed_at: DateTime<Utc>,
    pub remote_receipt: Option<RemoteReceiptSummary>,
    pub failure: Option<SanitizedFailure>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptKind {
    Delivered,
    Bounced,
    Rejected,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EmailReceiptObserved {
    pub delivery_id: String,
    pub attempt_id: String,
    pub function_run_id: String,
    pub kind: ReceiptKind,
    pub source: String,
    pub observed_at: DateTime<Utc>,
    pub remote_id: String,
    pub digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OrganizationInvitationLifecycle {
    pub invitation_id: String,
    pub organization_id: String,
    #[serde(alias = "acceptedAt", alias = "expiredAt", alias = "revokedAt")]
    pub observed_at: DateTime<Utc>,
}
