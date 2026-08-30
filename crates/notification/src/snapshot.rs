use aes_gcm::aead::{Aead as _, KeyInit as _};
use aes_gcm::{Aes256Gcm, Nonce};
use regex::Regex;
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use crate::error::{ErrorCode, NotificationError, NotificationResult};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtectedValue {
    pub ciphertext: String,
    pub key_reference: String,
}

pub trait SnapshotProtector: std::fmt::Debug + Send + Sync {
    fn protect(&self, plaintext: &str) -> NotificationResult<ProtectedValue>;
    fn reveal(&self, protected: &ProtectedValue) -> NotificationResult<String>;
}

#[derive(Clone)]
pub struct AeadSnapshotProtector {
    key: Zeroizing<[u8; 32]>,
    key_reference: String,
}

impl std::fmt::Debug for AeadSnapshotProtector {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AeadSnapshotProtector")
            .field("key_reference", &self.key_reference)
            .finish_non_exhaustive()
    }
}

impl AeadSnapshotProtector {
    pub fn from_base64_key(encoded: &str, key_reference: String) -> NotificationResult<Self> {
        use base64::Engine as _;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|error| {
                NotificationError::new(
                    ErrorCode::Validation,
                    "Notification snapshot key must be base64",
                )
                .with_source(error)
            })?;
        let key: [u8; 32] = bytes.try_into().map_err(|_| {
            NotificationError::new(
                ErrorCode::Validation,
                "Notification snapshot key must contain exactly 32 bytes",
            )
        })?;
        Ok(Self {
            key: Zeroizing::new(key),
            key_reference,
        })
    }
}

impl SnapshotProtector for AeadSnapshotProtector {
    fn protect(&self, plaintext: &str) -> NotificationResult<ProtectedValue> {
        use base64::Engine as _;
        let cipher = Aes256Gcm::new_from_slice(self.key.as_ref()).map_err(|_| {
            NotificationError::new(
                ErrorCode::Validation,
                "Notification snapshot key is invalid",
            )
        })?;
        let mut nonce_bytes = [0_u8; 12];
        getrandom::fill(&mut nonce_bytes).map_err(|error| {
            NotificationError::new(
                ErrorCode::Internal,
                "Notification snapshot nonce generation failed",
            )
            .with_source(error)
        })?;
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce_bytes), plaintext.as_bytes())
            .map_err(|_| {
                NotificationError::new(
                    ErrorCode::Internal,
                    "Notification snapshot encryption failed",
                )
            })?;
        let mut envelope = nonce_bytes.to_vec();
        envelope.extend(ciphertext);
        Ok(ProtectedValue {
            ciphertext: format!(
                "v1:{}",
                base64::engine::general_purpose::STANDARD.encode(envelope)
            ),
            key_reference: self.key_reference.clone(),
        })
    }

    fn reveal(&self, protected: &ProtectedValue) -> NotificationResult<String> {
        use base64::Engine as _;
        if protected.key_reference != self.key_reference {
            return Err(NotificationError::new(
                ErrorCode::Validation,
                "Notification snapshot key reference does not match",
            ));
        }
        let encoded = protected.ciphertext.strip_prefix("v1:").ok_or_else(|| {
            NotificationError::new(
                ErrorCode::Validation,
                "Notification snapshot envelope version is unsupported",
            )
        })?;
        let envelope = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|error| {
                NotificationError::new(ErrorCode::Validation, "invalid protected snapshot")
                    .with_source(error)
            })?;
        if envelope.len() <= 12 {
            return Err(NotificationError::new(
                ErrorCode::Validation,
                "invalid protected snapshot envelope",
            ));
        }
        let (nonce_bytes, ciphertext) = envelope.split_at(12);
        let cipher = Aes256Gcm::new_from_slice(self.key.as_ref()).map_err(|_| {
            NotificationError::new(
                ErrorCode::Validation,
                "Notification snapshot key is invalid",
            )
        })?;
        let plaintext = cipher
            .decrypt(Nonce::from_slice(nonce_bytes), ciphertext)
            .map_err(|_| {
                NotificationError::new(
                    ErrorCode::Validation,
                    "Notification snapshot authentication failed",
                )
            })?;
        String::from_utf8(plaintext).map_err(|error| {
            NotificationError::new(ErrorCode::Validation, "invalid protected snapshot encoding")
                .with_source(error)
        })
    }
}

/// Explicitly test-only protector. Production composition must inject an AEAD
/// envelope implementation whose key is resolved from a secret reference.
#[cfg(test)]
#[derive(Debug, Default)]
pub struct TestSnapshotProtector;

#[cfg(test)]
impl SnapshotProtector for TestSnapshotProtector {
    fn protect(&self, plaintext: &str) -> NotificationResult<ProtectedValue> {
        use base64::Engine as _;
        Ok(ProtectedValue {
            ciphertext: base64::engine::general_purpose::STANDARD.encode(plaintext),
            key_reference: "test-only:base64".to_owned(),
        })
    }

    fn reveal(&self, protected: &ProtectedValue) -> NotificationResult<String> {
        use base64::Engine as _;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(&protected.ciphertext)
            .map_err(|error| {
                NotificationError::new(ErrorCode::Validation, "invalid protected snapshot")
                    .with_source(error)
            })?;
        String::from_utf8(bytes).map_err(|error| {
            NotificationError::new(ErrorCode::Validation, "invalid protected snapshot encoding")
                .with_source(error)
        })
    }
}

pub fn content_digest(subject: &str, text: &str, html: &str) -> String {
    let mut hasher = Sha256::new();
    for part in [subject, text, html] {
        hasher.update(u64::try_from(part.len()).unwrap_or(u64::MAX).to_be_bytes());
        hasher.update(part.as_bytes());
    }
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

pub fn request_digest(serializable: &impl serde::Serialize) -> NotificationResult<String> {
    let encoded = serde_json::to_vec(serializable).map_err(|error| {
        NotificationError::new(ErrorCode::Validation, "intent request cannot be serialized")
            .with_source(error)
    })?;
    Ok(format!("sha256:{}", hex::encode(Sha256::digest(encoded))))
}

pub fn mask_email(address: &str) -> String {
    let Some((local, domain)) = address.rsplit_once('@') else {
        return "***".to_owned();
    };
    let first = local.chars().next().unwrap_or('*');
    format!("{first}***@{domain}")
}

pub fn redact_preview(text: &str) -> String {
    let url = Regex::new(r"https?://\S+").expect("valid URL redaction regex");
    let email = Regex::new(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
        .expect("valid email redaction regex");
    let without_urls = url.replace_all(text, "[link redacted]");
    let without_emails = email.replace_all(&without_urls, "[recipient redacted]");
    without_emails.chars().take(160).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preview_and_recipient_mask_hide_token_and_address() {
        let input = "Join at https://example.test/invitations/secret-token for alice@example.com";
        let preview = redact_preview(input);
        assert!(!preview.contains("secret-token"));
        assert!(!preview.contains("alice@example.com"));
        assert_eq!(mask_email("alice@example.com"), "a***@example.com");
    }

    #[test]
    fn production_envelope_round_trips_without_plaintext() {
        use base64::Engine as _;
        let key = base64::engine::general_purpose::STANDARD.encode([7_u8; 32]);
        let protector =
            AeadSnapshotProtector::from_base64_key(&key, "secret:test-notification-key".to_owned())
                .expect("protector");
        let protected = protector
            .protect("https://example.test/invitations/secret")
            .expect("protected");
        assert!(!protected.ciphertext.contains("secret"));
        assert_eq!(
            protector.reveal(&protected).expect("revealed"),
            "https://example.test/invitations/secret"
        );
    }
}
