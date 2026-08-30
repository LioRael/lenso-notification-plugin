use std::{error::Error, fmt};

/// Stable internal classification used to map Notification failures onto
/// Capability Domain Errors without leaking storage or payload details.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErrorCode {
    Validation,
    NotFound,
    Conflict,
    EvidenceOverflow,
    Internal,
}

/// One private Notification implementation failure.
#[derive(Debug)]
pub struct NotificationError {
    pub code: ErrorCode,
    message: String,
    source: Option<Box<dyn Error + Send + Sync>>,
}

impl NotificationError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            source: None,
        }
    }

    pub fn with_source(mut self, source: impl Error + Send + Sync + 'static) -> Self {
        self.source = Some(Box::new(source));
        self
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for NotificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Error for NotificationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.source
            .as_deref()
            .map(|source| source as &(dyn Error + 'static))
    }
}

impl From<sqlx::Error> for NotificationError {
    fn from(source: sqlx::Error) -> Self {
        Self::new(ErrorCode::Internal, "Notification storage operation failed").with_source(source)
    }
}

pub type NotificationResult<T> = Result<T, NotificationError>;
