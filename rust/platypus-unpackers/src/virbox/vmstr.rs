//! Virbox VME `vm_str` string deobfuscator (Report §7).
//!
//! Statically reproduces `F<buildId>_11(String)String` — the only one of
//! the 16 dispatchers whose body is implemented purely in Dalvik and so
//! is reversible without running the SO's VME interpreter.
//!
//! Algorithm (FINDINGS_REVIEW §11a):
//!
//! ```text
//!     input = "<deco><key_char><hex>"
//!     ct    = bytes.fromhex(input[2:])
//!     key   = ord(input[1])
//!     pt[i] = ((ct[i] - i) & 0xFF) ^ key
//! ```
//!
//! The leading "deco" character is decorative — only `input[1]` (the
//! key char) and `input[2..]` (the hex payload) participate.

/// Try to decode a `vm_str`-encoded payload to UTF-8 plaintext.
///
/// Returns `None` if the input doesn't conform to the encoding (which
/// is the normal flag for "this is a plain Java string, leave it
/// alone"): too short, odd-length hex, non-hex digits, non-UTF-8 result,
/// or control chars below 0x09 in the plaintext.
pub fn vm_str_decode(encoded: &str) -> Option<String> {
    let bytes = encoded.as_bytes();
    if bytes.len() < 2 {
        return None;
    }
    // The Python uses `ord(input[1])` on a str — for ASCII keys this is
    // just the byte. For multi-byte UTF-8 the Python str-index would be
    // a code point, but in practice every observed key char is ASCII
    // (it's a Java identifier byte). Treat non-ASCII as a malformed
    // input (returns None).
    let key_byte = bytes[1];
    if key_byte >= 0x80 {
        return None;
    }
    let hex_part = &encoded[2..];
    if hex_part.is_empty() || hex_part.len() % 2 != 0 {
        return None;
    }
    let ct = match hex_decode(hex_part) {
        Some(v) => v,
        None => return None,
    };
    let pt: Vec<u8> = ct
        .iter()
        .enumerate()
        .map(|(i, &c)| (c.wrapping_sub(i as u8)) ^ key_byte)
        .collect();
    // Reject if any control char below tab (matches the Python's
    // `if any(b < 0x09 for b in pt)` rejection).
    if pt.iter().any(|&b| b < 0x09) {
        return None;
    }
    // Final UTF-8 validation.
    String::from_utf8(pt).ok()
}

/// Strict hex decoder — returns None on any non-hex character. Matches
/// `bytes.fromhex` semantics modulo whitespace (we don't accept
/// whitespace, but neither does the Python here because the input is
/// always tight).
fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for chunk in bytes.chunks_exact(2) {
        let hi = nibble(chunk[0])?;
        let lo = nibble(chunk[1])?;
        out.push((hi << 4) | lo);
    }
    Some(out)
}

fn nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Known-vector captured from the Python reference implementation:
    /// `vm_str_decode("0A09252f3032")` decodes to `"Hello"` under key
    /// byte `'A'`. See the docstring header for the algorithm.
    #[test]
    fn vm_str_decode_known_vector() {
        assert_eq!(vm_str_decode("0A09252f3032").as_deref(), Some("Hello"));
    }

    #[test]
    fn vm_str_decode_rejects_too_short() {
        assert_eq!(vm_str_decode(""), None);
        assert_eq!(vm_str_decode("0"), None);
    }

    #[test]
    fn vm_str_decode_rejects_odd_hex() {
        // "0A" + "9" — hex part is one char, odd.
        assert_eq!(vm_str_decode("0A9"), None);
    }

    #[test]
    fn vm_str_decode_rejects_non_hex() {
        assert_eq!(vm_str_decode("0AZZ"), None);
    }

    #[test]
    fn vm_str_decode_rejects_control_chars() {
        // Encode a string whose first plaintext byte is 0x01 (below 0x09).
        // pt = b"\x01A", key='K' → ct[i] = ((pt[i] ^ key) + i) & 0xff
        let key = b'K';
        let pt = b"\x01A";
        let ct: Vec<u8> = pt
            .iter()
            .enumerate()
            .map(|(i, &p)| ((p ^ key) as usize + i) as u8)
            .collect();
        let hex: String = ct.iter().map(|b| format!("{:02x}", b)).collect();
        let encoded = format!("0K{}", hex);
        assert_eq!(vm_str_decode(&encoded), None);
    }
}
