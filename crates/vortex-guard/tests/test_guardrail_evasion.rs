use bytes::Bytes;
use vortex_guard::canonicalizer::WireCanonicalizer;
use vortex_guard::validator::{IngressValidator, ValidationConfig, ValidationOutcome};

#[test]
fn test_ingress_unicode_smuggling_and_sanitization() {
    let config = ValidationConfig {
        scan_pii: true,
        pii_quarantine: false, // In masking mode, secrets should be sanitized rather than outright dropped
        ..Default::default()
    };
    let validator = IngressValidator::new(config);

    // 1. Unicode zero-width evasion test:
    // Smuggled Anthropic API key with zero-width spaces (\u{200B}) interspersed
    let smuggled_input = "Here is the key: sk-\u{200B}ant-\u{200C}api03-abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
    let canonical = WireCanonicalizer::canonicalize(smuggled_input);
    assert!(!canonical.contains('\u{200B}'));
    assert!(!canonical.contains('\u{200C}'));
    assert!(canonical.contains("sk-ant-api03-"));

    // 2. Base64 obfuscation test:
    // AWS Key AKIAIOSFODNN7EXAMPLE base64-encoded is QUtJQUlPU0ZPRE5ON0VYQU1QTEU=
    let b64_payload = "Config secret: QUtJQUlPU0ZPRE5ON0VYQU1QTEU=";
    let decoded = WireCanonicalizer::decode_layers(b64_payload);
    assert!(decoded.iter().any(|layer| layer.contains("AKIAIOSFODNN7EXAMPLE")));

    // 3. ValidationOutcome propagation test:
    // When a payload contains a secret, validator::validate_outcome must return ValidationOutcome::Sanitized
    let payload = Bytes::from("Access granted: sk-ant-api03-sampletoken99812938192839182391823918239182391823918239182391823918239182391823918239182391823");
    let outcome = validator.validate_outcome("test-topic", None, &payload).expect("should succeed in masking mode");

    match outcome {
        ValidationOutcome::Sanitized(clean_bytes) => {
            let clean_str = std::str::from_utf8(&clean_bytes).unwrap();
            assert!(!clean_str.contains("sk-ant-api03-sampletoken"));
            assert!(clean_str.contains("[REDACTED"));
        }
        _ => panic!("Expected ValidationOutcome::Sanitized, got {:?}", outcome),
    }
}

