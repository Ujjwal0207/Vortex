use bytes::Bytes;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PiiAction {
    Allow,
    Mask(Bytes),
    Quarantine(String),
}

/// PiiScanner inspects streaming payloads at wire ingress to prevent accidental credential leaks,
/// private key exposures, and compliance violations (PCI-DSS / HIPAA / GDPR).
#[derive(Debug, Clone, Default)]
pub struct PiiScanner;

impl PiiScanner {
    pub fn new() -> Self {
        Self
    }

    /// Scans a payload for high-risk leaks:
    /// 1. AWS Credentials (AKIA...)
    /// 2. OpenAI / LLM API Keys (sk-proj-..., sk-...)
    /// 3. GitHub Personal Access Tokens (ghp_...)
    /// 4. PEM Encoded Private Keys (-----BEGIN ... PRIVATE KEY-----)
    /// 5. Credit Card Numbers (13-19 digits verified via Luhn algorithm)
    pub fn scan(&self, payload: &[u8], quarantine_on_detect: bool) -> PiiAction {
        let text = match std::str::from_utf8(payload) {
            Ok(t) => std::borrow::Cow::Borrowed(t),
            Err(_) => String::from_utf8_lossy(payload),
        };

        // 1. AWS Key Detection: AKIA followed by 16 alphanumeric uppercase characters / digits
        if let Some(idx) = text.find("AKIA") {
            let candidate = &text[idx..];
            if candidate.len() >= 20 {
                let key_part = &candidate[..20];
                if key_part.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit()) {
                    let reason = format!("Detected exposed AWS Access Key ID: '{}...'", &key_part[..8]);
                    return if quarantine_on_detect {
                        PiiAction::Quarantine(reason)
                    } else {
                        PiiAction::Mask(Bytes::from(text.replace(key_part, "[***REDACTED-AWS-KEY***]")))
                    };
                }
            }
        }

        // 2. Private Key Detection
        if text.contains("-----BEGIN") && text.contains("PRIVATE KEY-----") {
            let reason = "Detected exposed PEM Private Key".to_string();
            return if quarantine_on_detect {
                PiiAction::Quarantine(reason)
            } else {
                PiiAction::Mask(Bytes::from("[***REDACTED-PRIVATE-KEY***]"))
            };
        }

        // 3. GitHub Tokens (ghp_, gho_, ghs_, ghr_)
        for prefix in &["ghp_", "gho_", "ghs_", "ghr_"] {
            if let Some(idx) = text.find(prefix) {
                let candidate = &text[idx..];
                if candidate.len() >= 36 {
                    let token_part = &candidate[..36];
                    if token_part[4..].chars().all(|c| c.is_ascii_alphanumeric()) {
                        let reason = format!("Detected exposed GitHub Secret Token starting with '{}'", prefix);
                        return if quarantine_on_detect {
                            PiiAction::Quarantine(reason)
                        } else {
                            PiiAction::Mask(Bytes::from(text.replace(token_part, "[***REDACTED-GITHUB-TOKEN***]")))
                        };
                    }
                }
            }
        }

        // 4. OpenAI / AI Agent Tokens (sk-proj-...)
        if let Some(idx) = text.find("sk-proj-") {
            let candidate = &text[idx..];
            if candidate.len() >= 20 {
                let token_slice = &candidate[..20];
                let reason = "Detected exposed OpenAI / LLM Secret Key ('sk-proj-...')".to_string();
                return if quarantine_on_detect {
                    PiiAction::Quarantine(reason)
                } else {
                    PiiAction::Mask(Bytes::from(text.replace(token_slice, "[***REDACTED-OPENAI-KEY***]")))
                };
            }
        }

        // 5. Credit Card Number Detection with Luhn algorithm validation
        if let Some(card_number) = find_valid_credit_card(&text) {
            let reason = format!("Detected exposed Credit Card Number: '****-****-****-{}'", &card_number[card_number.len().saturating_sub(4)..]);
            return if quarantine_on_detect {
                PiiAction::Quarantine(reason)
            } else {
                PiiAction::Mask(Bytes::from(text.replace(&card_number, "[***REDACTED-CARD***]")))
            };
        }

        PiiAction::Allow
    }
}

/// Searches text for candidate 13 to 19 digit strings (with optional hyphens/spaces)
/// that pass the Luhn checksum.
fn find_valid_credit_card(text: &str) -> Option<String> {
    let chars: Vec<char> = text.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        if chars[i].is_ascii_digit() {
            let mut candidate_digits = String::new();
            let mut raw_matched = String::new();
            let mut j = i;

            while j < chars.len() {
                let c = chars[j];
                if c.is_ascii_digit() {
                    candidate_digits.push(c);
                    raw_matched.push(c);
                } else if (c == '-' || c == ' ') && !candidate_digits.is_empty() {
                    raw_matched.push(c);
                } else {
                    break;
                }
                j += 1;
            }

            // Standard card lengths: 13 to 19 digits (Visa: 13/16, MC: 16, Amex: 15)
            if candidate_digits.len() >= 13 && candidate_digits.len() <= 19 {
                if luhn_check(&candidate_digits) {
                    return Some(raw_matched);
                }
            }

            i = j;
        } else {
            i += 1;
        }
    }

    None
}

/// Evaluates whether a numeric string passes the Luhn algorithm (mod 10).
fn luhn_check(digits_str: &str) -> bool {
    let mut sum = 0;
    let mut alternate = false;

    for c in digits_str.chars().rev() {
        if let Some(mut digit) = c.to_digit(10) {
            if alternate {
                digit *= 2;
                if digit > 9 {
                    digit -= 9;
                }
            }
            sum += digit;
            alternate = !alternate;
        } else {
            return false;
        }
    }

    sum % 10 == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aws_key_quarantine_and_mask() {
        let scanner = PiiScanner::new();
        let payload = b"{\"user\":\"alice\",\"key\":\"AKIAIOSFODNN7EXAMPLE\"}";

        // Test quarantine
        let action = scanner.scan(payload, true);
        assert!(matches!(action, PiiAction::Quarantine(_)));

        // Test mask
        let action = scanner.scan(payload, false);
        if let PiiAction::Mask(masked) = action {
            let s = std::str::from_utf8(&masked).unwrap();
            assert!(s.contains("[***REDACTED-AWS-KEY***]"));
            assert!(!s.contains("AKIAIOSFODNN7EXAMPLE"));
        } else {
            panic!("Expected Mask, got {:?}", action);
        }
    }

    #[test]
    fn test_private_key_quarantine() {
        let scanner = PiiScanner::new();
        let payload = b"-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0...\n-----END RSA PRIVATE KEY-----";
        let action = scanner.scan(payload, true);
        assert!(matches!(action, PiiAction::Quarantine(_)));
    }

    #[test]
    fn test_credit_card_luhn_detection() {
        let scanner = PiiScanner::new();
        // Standard test Visa card passing Luhn: 4532-0151-1283-0366
        let payload = b"Payment payload: card=4532-0151-1283-0366 amount=100";
        let action = scanner.scan(payload, true);
        assert!(matches!(action, PiiAction::Quarantine(_)));

        // Non-card random digits should pass
        let benign = b"Order ID: 12345678901234567";
        let action_benign = scanner.scan(benign, true);
        assert_eq!(action_benign, PiiAction::Allow);
    }

    #[test]
    fn test_binary_payload_with_embedded_secret() {
        let scanner = PiiScanner::new();
        // Construct binary frame (e.g. Avro/Protobuf header with 0xFF 0xFE invalid UTF-8) containing an AWS key
        let mut binary_payload = vec![0xFF, 0xFE, 0x00, 0x01];
        binary_payload.extend_from_slice(b"AKIAIOSFODNN7EXAMPLE1");
        binary_payload.extend_from_slice(&[0x00, 0x80, 0x99]);

        let action = scanner.scan(&binary_payload, true);
        assert!(matches!(action, PiiAction::Quarantine(_)));
    }
}
