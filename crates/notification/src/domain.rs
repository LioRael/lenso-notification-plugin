use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryStatus {
    Queued,
    Attempting,
    Accepted,
    RetryScheduled,
    Delivered,
    Failed,
    DeliveryUnknown,
}

impl DeliveryStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Attempting => "attempting",
            Self::Accepted => "accepted",
            Self::RetryScheduled => "retry_scheduled",
            Self::Delivered => "delivered",
            Self::Failed => "failed",
            Self::DeliveryUnknown => "delivery_unknown",
        }
    }

    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Delivered | Self::Failed | Self::DeliveryUnknown)
    }
}

impl std::str::FromStr for DeliveryStatus {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "queued" => Ok(Self::Queued),
            "attempting" => Ok(Self::Attempting),
            "accepted" => Ok(Self::Accepted),
            "retry_scheduled" => Ok(Self::RetryScheduled),
            "delivered" => Ok(Self::Delivered),
            "failed" => Ok(Self::Failed),
            "delivery_unknown" => Ok(Self::DeliveryUnknown),
            _ => Err("unknown delivery status"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttemptStatus {
    Dispatching,
    Accepted,
    TemporaryFailure,
    PermanentFailure,
    DeliveryUnknown,
}

impl AttemptStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Dispatching => "dispatching",
            Self::Accepted => "accepted",
            Self::TemporaryFailure => "temporary_failure",
            Self::PermanentFailure => "permanent_failure",
            Self::DeliveryUnknown => "delivery_unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetryKind {
    Automatic,
    Manual,
}

impl RetryKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Automatic => "automatic",
            Self::Manual => "manual",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetryPolicy {
    pub max_attempts: i32,
    pub delays_seconds: Vec<i64>,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 4,
            delays_seconds: vec![60, 300, 1_800],
        }
    }
}

impl RetryPolicy {
    pub fn next_at(&self, completed_attempt: i32, now: DateTime<Utc>) -> Option<DateTime<Utc>> {
        if completed_attempt >= self.max_attempts {
            return None;
        }
        let index = usize::try_from(completed_attempt.saturating_sub(1)).ok()?;
        self.delays_seconds
            .get(index)
            .map(|seconds| now + chrono::Duration::seconds(*seconds))
    }
}

pub fn can_transition(from: DeliveryStatus, to: DeliveryStatus) -> bool {
    matches!(
        (from, to),
        (
            DeliveryStatus::Queued | DeliveryStatus::RetryScheduled,
            DeliveryStatus::Attempting
        ) | (
            DeliveryStatus::Attempting,
            DeliveryStatus::Accepted
                | DeliveryStatus::Delivered
                | DeliveryStatus::RetryScheduled
                | DeliveryStatus::Failed
                | DeliveryStatus::DeliveryUnknown
        ) | (
            DeliveryStatus::Accepted,
            DeliveryStatus::Delivered
                | DeliveryStatus::RetryScheduled
                | DeliveryStatus::Failed
                | DeliveryStatus::DeliveryUnknown
        ) | (DeliveryStatus::Failed, DeliveryStatus::RetryScheduled)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delivery_state_machine_rejects_regressions_and_unknown_retry() {
        assert!(can_transition(
            DeliveryStatus::Queued,
            DeliveryStatus::Attempting
        ));
        assert!(can_transition(
            DeliveryStatus::Accepted,
            DeliveryStatus::Delivered
        ));
        assert!(!can_transition(
            DeliveryStatus::Accepted,
            DeliveryStatus::Queued
        ));
        assert!(!can_transition(
            DeliveryStatus::DeliveryUnknown,
            DeliveryStatus::RetryScheduled
        ));
        assert!(!can_transition(
            DeliveryStatus::Delivered,
            DeliveryStatus::RetryScheduled
        ));
    }

    #[test]
    fn retry_policy_is_bounded() {
        let policy = RetryPolicy::default();
        let now = Utc::now();
        assert_eq!(
            policy.next_at(1, now),
            Some(now + chrono::Duration::seconds(60))
        );
        assert!(policy.next_at(4, now).is_none());
    }
}
