//! AES (FIPS-197) block cipher + CBC mode, encrypt and decrypt.
//!
//! Supports 128-bit and 256-bit keys. The public helpers cover the two
//! padding policies the codebase uses:
//!
//!   * [`aes_cbc_pkcs7_decrypt`] / [`aes_cbc_pkcs7_encrypt`] — for the
//!     VM's `Cipher.doFinal` mock (Java's default `AES/CBC/PKCS5Padding`).
//!   * [`aes_cbc_nopad_decrypt`] / [`aes_cbc_nopad_encrypt`] — for
//!     packers like Fengyue that store block-aligned ciphertext with no
//!     padding.

// ── Tables ──────────────────────────────────────────────────────────────────

/// AES S-box (FIPS-197 Figure 7).
const SBOX: [u8; 256] = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
];

/// Round constants for the key schedule.
const RCON: [u8; 11] = [
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
];

fn inv_sbox() -> [u8; 256] {
    let mut inv = [0u8; 256];
    for (i, &s) in SBOX.iter().enumerate() {
        inv[s as usize] = i as u8;
    }
    inv
}

/// GF(2^8) multiply in the Rijndael field (modulus 0x11b).
fn gmul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0u8;
    for _ in 0..8 {
        if b & 1 != 0 { p ^= a; }
        let hi = a & 0x80;
        a <<= 1;
        if hi != 0 { a ^= 0x1b; }
        b >>= 1;
    }
    p
}

// ── Cipher state ────────────────────────────────────────────────────────────

/// An AES instance holding the expanded key schedule. Reusable across
/// many blocks. Construct with [`Aes::new`].
pub struct Aes {
    round_keys: Vec<[u8; 16]>,
    rounds: usize,
    inv_sbox: [u8; 256],
}

impl Aes {
    /// Expand a 16-byte (AES-128) or 32-byte (AES-256) key. `None` for
    /// any other length.
    pub fn new(key: &[u8]) -> Option<Self> {
        let (nk, rounds) = match key.len() {
            16 => (4usize, 10usize),
            32 => (8usize, 14usize),
            _ => return None,
        };
        let total_words = 4 * (rounds + 1);
        let mut w: Vec<[u8; 4]> = Vec::with_capacity(total_words);
        for i in 0..nk {
            w.push([key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]]);
        }
        for i in nk..total_words {
            let mut temp = w[i - 1];
            if i % nk == 0 {
                temp = [temp[1], temp[2], temp[3], temp[0]];
                for b in &mut temp { *b = SBOX[*b as usize]; }
                temp[0] ^= RCON[i / nk];
            } else if nk > 6 && i % nk == 4 {
                for b in &mut temp { *b = SBOX[*b as usize]; }
            }
            let prev = w[i - nk];
            w.push([
                prev[0] ^ temp[0], prev[1] ^ temp[1],
                prev[2] ^ temp[2], prev[3] ^ temp[3],
            ]);
        }
        let mut round_keys = Vec::with_capacity(rounds + 1);
        for r in 0..=rounds {
            let mut rk = [0u8; 16];
            for c in 0..4 {
                rk[4 * c..4 * c + 4].copy_from_slice(&w[4 * r + c]);
            }
            round_keys.push(rk);
        }
        Some(Aes { round_keys, rounds, inv_sbox: inv_sbox() })
    }

    /// Encrypt one 16-byte block in place (FIPS-197 §5.1).
    pub fn encrypt_block(&self, block: &mut [u8; 16]) {
        self.add_round_key(block, 0);
        for round in 1..self.rounds {
            sub_bytes(block);
            shift_rows(block);
            mix_columns(block);
            self.add_round_key(block, round);
        }
        sub_bytes(block);
        shift_rows(block);
        self.add_round_key(block, self.rounds);
    }

    /// Decrypt one 16-byte block in place (FIPS-197 §5.3).
    pub fn decrypt_block(&self, block: &mut [u8; 16]) {
        self.add_round_key(block, self.rounds);
        for round in (1..self.rounds).rev() {
            inv_shift_rows(block);
            inv_sub_bytes(block, &self.inv_sbox);
            self.add_round_key(block, round);
            inv_mix_columns(block);
        }
        inv_shift_rows(block);
        inv_sub_bytes(block, &self.inv_sbox);
        self.add_round_key(block, 0);
    }

    #[inline]
    fn add_round_key(&self, block: &mut [u8; 16], round: usize) {
        let rk = &self.round_keys[round];
        for i in 0..16 { block[i] ^= rk[i]; }
    }
}

// ── Round transforms ────────────────────────────────────────────────────────

#[inline]
fn sub_bytes(b: &mut [u8; 16]) {
    for x in b.iter_mut() { *x = SBOX[*x as usize]; }
}
#[inline]
fn inv_sub_bytes(b: &mut [u8; 16], inv: &[u8; 256]) {
    for x in b.iter_mut() { *x = inv[*x as usize]; }
}

/// ShiftRows. State is column-major: byte i is row i%4, column i/4.
#[inline]
fn shift_rows(s: &mut [u8; 16]) {
    let t = [s[1], s[5], s[9], s[13]];
    s[1] = t[1]; s[5] = t[2]; s[9] = t[3]; s[13] = t[0];   // row 1 left-rot 1
    let t = [s[2], s[6], s[10], s[14]];
    s[2] = t[2]; s[6] = t[3]; s[10] = t[0]; s[14] = t[1];  // row 2 left-rot 2
    let t = [s[3], s[7], s[11], s[15]];
    s[3] = t[3]; s[7] = t[0]; s[11] = t[1]; s[15] = t[2];  // row 3 left-rot 3
}

#[inline]
fn inv_shift_rows(s: &mut [u8; 16]) {
    let t = [s[1], s[5], s[9], s[13]];
    s[1] = t[3]; s[5] = t[0]; s[9] = t[1]; s[13] = t[2];   // row 1 right-rot 1
    let t = [s[2], s[6], s[10], s[14]];
    s[2] = t[2]; s[6] = t[3]; s[10] = t[0]; s[14] = t[1];  // row 2 right-rot 2
    let t = [s[3], s[7], s[11], s[15]];
    s[3] = t[1]; s[7] = t[2]; s[11] = t[3]; s[15] = t[0];  // row 3 right-rot 3
}

#[inline]
fn mix_columns(s: &mut [u8; 16]) {
    for c in 0..4 {
        let i = 4 * c;
        let a0 = s[i]; let a1 = s[i + 1]; let a2 = s[i + 2]; let a3 = s[i + 3];
        s[i]     = gmul(a0, 2) ^ gmul(a1, 3) ^ a2 ^ a3;
        s[i + 1] = a0 ^ gmul(a1, 2) ^ gmul(a2, 3) ^ a3;
        s[i + 2] = a0 ^ a1 ^ gmul(a2, 2) ^ gmul(a3, 3);
        s[i + 3] = gmul(a0, 3) ^ a1 ^ a2 ^ gmul(a3, 2);
    }
}

#[inline]
fn inv_mix_columns(s: &mut [u8; 16]) {
    for c in 0..4 {
        let i = 4 * c;
        let a0 = s[i]; let a1 = s[i + 1]; let a2 = s[i + 2]; let a3 = s[i + 3];
        s[i]     = gmul(a0, 14) ^ gmul(a1, 11) ^ gmul(a2, 13) ^ gmul(a3, 9);
        s[i + 1] = gmul(a0, 9)  ^ gmul(a1, 14) ^ gmul(a2, 11) ^ gmul(a3, 13);
        s[i + 2] = gmul(a0, 13) ^ gmul(a1, 9)  ^ gmul(a2, 14) ^ gmul(a3, 11);
        s[i + 3] = gmul(a0, 11) ^ gmul(a1, 13) ^ gmul(a2, 9)  ^ gmul(a3, 14);
    }
}

// ── CBC + padding ───────────────────────────────────────────────────────────

/// AES-CBC decrypt, no padding removal. `ciphertext.len()` must be a
/// non-zero multiple of 16; `key` 16 or 32 bytes. Returns the raw
/// plaintext (still includes any padding the caller chose to ignore).
pub fn aes_cbc_nopad_decrypt(key: &[u8], iv: &[u8; 16], ciphertext: &[u8]) -> Option<Vec<u8>> {
    let aes = Aes::new(key)?;
    if ciphertext.is_empty() || ciphertext.len() % 16 != 0 { return None; }
    let mut out = Vec::with_capacity(ciphertext.len());
    let mut prev = *iv;
    for chunk in ciphertext.chunks_exact(16) {
        let mut block: [u8; 16] = chunk.try_into().ok()?;
        let cipher_block = block;
        aes.decrypt_block(&mut block);
        for i in 0..16 { block[i] ^= prev[i]; }
        out.extend_from_slice(&block);
        prev = cipher_block;
    }
    Some(out)
}

/// AES-CBC encrypt, no padding. `plaintext` must already be block
/// aligned (a multiple of 16, non-zero). Used by round-trip tests + any
/// caller that pads itself.
pub fn aes_cbc_nopad_encrypt(key: &[u8], iv: &[u8; 16], plaintext: &[u8]) -> Option<Vec<u8>> {
    let aes = Aes::new(key)?;
    if plaintext.is_empty() || plaintext.len() % 16 != 0 { return None; }
    let mut out = Vec::with_capacity(plaintext.len());
    let mut prev = *iv;
    for chunk in plaintext.chunks_exact(16) {
        let mut block: [u8; 16] = chunk.try_into().ok()?;
        for i in 0..16 { block[i] ^= prev[i]; }
        aes.encrypt_block(&mut block);
        out.extend_from_slice(&block);
        prev = block;
    }
    Some(out)
}

/// AES-CBC decrypt + strip PKCS#7 padding. Returns `None` on bad
/// lengths or invalid padding (mirrors the old RustCrypto
/// `decrypt_padded` behaviour).
pub fn aes_cbc_pkcs7_decrypt(key: &[u8], iv: &[u8; 16], ciphertext: &[u8]) -> Option<Vec<u8>> {
    let mut out = aes_cbc_nopad_decrypt(key, iv, ciphertext)?;
    strip_pkcs7(&mut out)?;
    Some(out)
}

/// AES-CBC encrypt with PKCS#7 padding applied first. Plaintext may be
/// any length. Used by round-trip tests.
pub fn aes_cbc_pkcs7_encrypt(key: &[u8], iv: &[u8; 16], plaintext: &[u8]) -> Option<Vec<u8>> {
    let pad = 16 - (plaintext.len() % 16);
    let mut padded = Vec::with_capacity(plaintext.len() + pad);
    padded.extend_from_slice(plaintext);
    padded.extend(std::iter::repeat(pad as u8).take(pad));
    aes_cbc_nopad_encrypt(key, iv, &padded)
}

fn strip_pkcs7(buf: &mut Vec<u8>) -> Option<()> {
    let &pad = buf.last()?;
    let pad = pad as usize;
    if pad == 0 || pad > 16 || pad > buf.len() { return None; }
    let start = buf.len() - pad;
    if buf[start..].iter().any(|&b| b as usize != pad) { return None; }
    buf.truncate(start);
    Some(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// FIPS-197 Appendix C.1 (AES-128) single-block known answer — both
    /// directions.
    #[test]
    fn fips197_aes128_block_both_ways() {
        let key: [u8; 16] = [
            0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
            0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
        ];
        let pt: [u8; 16] = [
            0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
            0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,
        ];
        let ct: [u8; 16] = [
            0x69,0xc4,0xe0,0xd8,0x6a,0x7b,0x04,0x30,
            0xd8,0xcd,0xb7,0x80,0x70,0xb4,0xc5,0x5a,
        ];
        let aes = Aes::new(&key).unwrap();
        let mut e = pt; aes.encrypt_block(&mut e); assert_eq!(e, ct);
        let mut d = ct; aes.decrypt_block(&mut d); assert_eq!(d, pt);
    }

    /// FIPS-197 Appendix C.3 (AES-256) single-block known answer.
    #[test]
    fn fips197_aes256_block_both_ways() {
        let key: [u8; 32] = [
            0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
            0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
            0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
            0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,
        ];
        let pt: [u8; 16] = [
            0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
            0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,
        ];
        let ct: [u8; 16] = [
            0x8e,0xa2,0xb7,0xca,0x51,0x67,0x45,0xbf,
            0xea,0xfc,0x49,0x90,0x4b,0x49,0x60,0x89,
        ];
        let aes = Aes::new(&key).unwrap();
        let mut e = pt; aes.encrypt_block(&mut e); assert_eq!(e, ct);
        let mut d = ct; aes.decrypt_block(&mut d); assert_eq!(d, pt);
    }

    /// NIST SP 800-38A F.2.1/F.2.2 — CBC-AES128 multi-block, first block.
    #[test]
    fn sp800_38a_cbc_aes128_first_block() {
        let key: [u8; 16] = [
            0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
            0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c,
        ];
        let iv: [u8; 16] = [
            0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
            0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
        ];
        let pt: [u8; 16] = [
            0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,
            0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a,
        ];
        let ct: [u8; 16] = [
            0x76,0x49,0xab,0xac,0x81,0x19,0xb2,0x46,
            0xce,0xe9,0x8e,0x9b,0x12,0xe9,0x19,0x7d,
        ];
        let enc = aes_cbc_nopad_encrypt(&key, &iv, &pt).unwrap();
        assert_eq!(enc, ct);
        let dec = aes_cbc_nopad_decrypt(&key, &iv, &ct).unwrap();
        assert_eq!(dec, pt);
    }

    #[test]
    fn cbc_pkcs7_round_trip_128_and_256() {
        for key_len in [16usize, 32] {
            let key = vec![0x11u8; key_len];
            let iv = [0x22u8; 16];
            let msg = b"the quick brown fox jumps over 13 lazy dogs!!"; // 45 bytes
            let ct = aes_cbc_pkcs7_encrypt(&key, &iv, msg).unwrap();
            assert_eq!(ct.len() % 16, 0);
            let pt = aes_cbc_pkcs7_decrypt(&key, &iv, &ct).unwrap();
            assert_eq!(pt, msg);
        }
    }

    #[test]
    fn rejects_bad_inputs() {
        let key = [0u8; 16];
        let iv = [0u8; 16];
        assert!(aes_cbc_pkcs7_decrypt(&key, &iv, &[0u8; 17]).is_none());
        assert!(aes_cbc_pkcs7_decrypt(&key, &iv, &[]).is_none());
        assert!(aes_cbc_pkcs7_decrypt(&[0u8; 20], &iv, &[0u8; 16]).is_none());
        assert!(aes_cbc_nopad_encrypt(&key, &iv, &[0u8; 15]).is_none());
    }
}
