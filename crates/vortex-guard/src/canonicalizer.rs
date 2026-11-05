/// Wire Canonicalizer: Strips zero-width evasion characters and inspects decoded layers.
pub struct WireCanonicalizer;

impl WireCanonicalizer {
    /// Strips zero-width and invisible formatting characters to counter evasive obfuscation:
    /// - \u{200B} (Zero-Width Space)
    /// - \u{200C} (Zero-Width Non-Joiner)
    /// - \u{200D} (Zero-Width Joiner)
    /// - \u{FEFF} (Zero-Width No-Break Space / BOM)
    /// - \u{00AD} (Soft Hyphen)
    /// - \u{2060} (Word Joiner)
    pub fn canonicalize(input: &str) -> String {
        input
            .chars()
            .filter(|&c| {
                c != '\u{200B}'
                    && c != '\u{200C}'
                    && c != '\u{200D}'
                    && c != '\u{FEFF}'
                    && c != '\u{00AD}'
                    && c != '\u{2060}'
            })
            .collect()
    }

    /// Generates decoded views across Base64 and URL encoding layers to reveal hidden tokens.
    pub fn decode_layers(input: &str) -> Vec<String> {
        let mut layers = Vec::new();
        let canonical = Self::canonicalize(input);
        layers.push(canonical.clone());

        // Check for Base64 segments
        for word in canonical.split_whitespace() {
            let clean_word = word.trim_matches(|c: char| !c.is_alphanumeric() && c != '=' && c != '+' && c != '/');
            if clean_word.len() >= 16 && clean_word.len() % 4 == 0 {
                if let Ok(decoded_bytes) = simple_base64_decode(clean_word) {
                    if let Ok(decoded_str) = std::str::from_utf8(&decoded_bytes) {
                        layers.push(decoded_str.to_string());
                    }
                }
            }
        }

        // Check for URL percent-encoding
        if canonical.contains('%') {
            if let Some(decoded_url) = decode_percent(&canonical) {
                layers.push(decoded_url);
            }
        }

        layers
    }
}

fn b64_val(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

fn simple_base64_decode(input: &str) -> Result<Vec<u8>, ()> {
    let bytes = input.as_bytes();
    if bytes.len() % 4 != 0 {
        return Err(());
    }
    let mut out = Vec::with_capacity((bytes.len() / 4) * 3);
    for chunk in bytes.chunks_exact(4) {
        let b0 = b64_val(chunk[0]).ok_or(())?;
        let b1 = b64_val(chunk[1]).ok_or(())?;
        let b2 = if chunk[2] == b'=' { 0 } else { b64_val(chunk[2]).ok_or(())? };
        let b3 = if chunk[3] == b'=' { 0 } else { b64_val(chunk[3]).ok_or(())? };

        out.push((b0 << 2) | (b1 >> 4));
        if chunk[2] != b'=' {
            out.push((b1 << 4) | (b2 >> 2));
        }
        if chunk[3] != b'=' {
            out.push((b2 << 6) | b3);
        }
    }
    Ok(out)
}

fn decode_percent(input: &str) -> Option<String> {
    let mut bytes = Vec::new();
    let mut chars = input.bytes().peekable();
    while let Some(b) = chars.next() {
        if b == b'%' {
            let h1 = chars.next()?;
            let h2 = chars.next()?;
            let hex_buf = [h1, h2];
            let hex_str = std::str::from_utf8(&hex_buf).ok()?;
            let val = u8::from_str_radix(hex_str, 16).ok()?;
            bytes.push(val);
        } else {
            bytes.push(b);
        }
    }
    String::from_utf8(bytes).ok()
}
