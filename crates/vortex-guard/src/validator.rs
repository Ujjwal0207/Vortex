use bytes::Bytes;
use vortex_core::{error::Result, VortexError};

pub const DEFAULT_MAX_MESSAGE_SIZE: usize = 10 * 1024 * 1024; // 10 MB

#[derive(Debug, Clone)]
pub struct ValidationConfig {
    pub max_message_size: usize,
    pub enforce_utf8_json: bool,
    pub reject_empty_payload: bool,
}

impl Default for ValidationConfig {
    fn default() -> Self {
        Self {
            max_message_size: DEFAULT_MAX_MESSAGE_SIZE,
            enforce_utf8_json: false,
            reject_empty_payload: false,
        }
    }
}

pub struct IngressValidator {
    config: ValidationConfig,
}

impl IngressValidator {
    pub fn new(config: ValidationConfig) -> Self {
        Self { config }
    }

    /// Validates an incoming message at the wire boundary before it touches storage.
    /// Fast-path rejection for oversized messages, empty payloads (if configured),
    /// or structural corruption (poison pills).
    pub fn validate(&self, topic: &str, key: Option<&Bytes>, value: &Bytes) -> Result<()> {
        let total_size = key.map(|k| k.len()).unwrap_or(0) + value.len();

        // 1. Oversize check (prevents OOM memory exhaustion attacks)
        if total_size > self.config.max_message_size {
            return Err(VortexError::PoisonPillDetected {
                reason: format!(
                    "Message size ({} bytes) exceeds topic limit of {} bytes",
                    total_size, self.config.max_message_size
                ),
            });
        }

        // 2. Empty payload check
        if self.config.reject_empty_payload && value.is_empty() {
            return Err(VortexError::PoisonPillDetected {
                reason: "Empty payload rejected by topic policy".to_string(),
            });
        }

        // 3. Structural JSON sanity check (if enabled for topic)
        if self.config.enforce_utf8_json {
            let json_str = std::str::from_utf8(value).map_err(|_| VortexError::SchemaValidationFailed {
                topic: topic.to_string(),
                reason: "Payload is not valid UTF-8 JSON".to_string(),
            })?;

            // Fast structural check: must start and end with { } or [ ]
            let trimmed = json_str.trim();
            let is_object = trimmed.starts_with('{') && trimmed.ends_with('}');
            let is_array = trimmed.starts_with('[') && trimmed.ends_with(']');

            if !is_object && !is_array {
                return Err(VortexError::SchemaValidationFailed {
                    topic: topic.to_string(),
                    reason: "Malformed JSON structure: root must be an object or array".to_string(),
                });
            }

            // Rapid zero-allocation syntax validation
            if serde_json::from_str::<serde_json::Value>(trimmed).is_err() {
                return Err(VortexError::SchemaValidationFailed {
                    topic: topic.to_string(),
                    reason: "Syntax error in JSON payload (poison pill prevented)".to_string(),
                });
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_oversize_message_quarantined() {
        let config = ValidationConfig {
            max_message_size: 100,
            ..Default::default()
        };
        let validator = IngressValidator::new(config);

        let valid_payload = Bytes::from(vec![0u8; 50]);
        assert!(validator.validate("events", None, &valid_payload).is_ok());

        let toxic_payload = Bytes::from(vec![0u8; 150]);
        let err = validator.validate("events", None, &toxic_payload);
        assert!(matches!(err, Err(VortexError::PoisonPillDetected { .. })));
    }

    #[test]
    fn test_json_poison_pill_blocked() {
        let config = ValidationConfig {
            enforce_utf8_json: true,
            ..Default::default()
        };
        let validator = IngressValidator::new(config);

        let good_json = Bytes::from_static(b"{\"user_id\": 102, \"action\": \"login\"}");
        assert!(validator.validate("auth-events", None, &good_json).is_ok());

        // Broken JSON (poison pill) that would crash standard consumers
        let broken_json = Bytes::from_static(b"{\"user_id\": 102, \"action\": unquoted_garbage}");
        let err = validator.validate("auth-events", None, &broken_json);
        assert!(matches!(err, Err(VortexError::SchemaValidationFailed { .. })));
    }
}
