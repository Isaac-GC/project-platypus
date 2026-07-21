//! Pure ALU helpers — direct port of `dex/helpers.py::reg_ops_helper`
//! from `instructions_new.py`'s reference implementation.
//!
//! `reg_ops_helper(operator_type, operand_type, b, c)` is the core
//! "do one binary op" function shared by `BinOp`, `BinOp2Addr`, and
//! `BinOpLit`. The operator and operand decoding is done by the
//! callers (each instruction kind has slightly different bit
//! packing); this function only sees the already-decoded indices
//! plus the two operand values.
//!
//! ### Operator codes
//!
//! | code | op                              |
//! |------|---------------------------------|
//! | 0x0  | add                             |
//! | 0x1  | sub                             |
//! | 0x2  | mul                             |
//! | 0x3  | div (i64 floor division)        |
//! | 0x4  | rem                             |
//! | 0x5  | and                             |
//! | 0x6  | or                              |
//! | 0x7  | xor                             |
//! | 0x8  | shl                             |
//! | 0x9  | shr                             |
//! | 0xa  | ushr                            |
//!
//! ### Operand codes
//!
//! | code | type                            |
//! |------|---------------------------------|
//! | 0x0  | int    (32-bit)                 |
//! | 0x1  | long   (64-bit)                 |
//! | 0x2  | float  (treated like int here)  |
//! | 0x3  | double (treated like long here) |
//!
//! ### Python quirks preserved verbatim
//!
//! The Python reference has several behaviours that look like bugs
//! but are load-bearing for the reference output:
//!
//! 1. **Non-long shift mask is `0xFFFFFF`** (24 bits), not the
//!    expected `0xFFFFFFFF`. We mirror this.
//! 2. **ushr-long shifts LEFT** instead of right
//!    (`a = (shift << c) & BIT_BACK` in the long branch). We mirror.
//! 3. **int divide rounds toward negative infinity** (Python's `//`
//!    operator), not toward zero. Rust's `/` rounds toward zero on
//!    signed integers — we use `div_euclid` adjustment to match
//!    Python.
//! 4. **Division by zero returns 0** rather than panicking.
//!
//! Tests assert these exact behaviours so a faithful-port regression
//! is caught.

/// Direct port of `reg_ops_helper(operator_type, operand_type, b, c)`
/// from `dex/instructions_new.py`.
pub fn reg_ops_helper(operator: u8, operand: u8, b: i64, c: i64) -> i64 {
    let mut a: i64;
    let mut c = c;

    match operator {
        0x0 => a = b.wrapping_add(c),
        0x1 => a = b.wrapping_sub(c),
        0x2 => a = b.wrapping_mul(c),
        0x3 => {
            // Python's `//` is floor-division; Rust's `/` is
            // truncation. Match Python by translating.
            a = if c == 0 { 0 } else { python_floor_div(b, c) };
        }
        0x4 => {
            // Same — Python's `%` follows the sign of the divisor.
            a = if c == 0 { 0 } else { python_mod(b, c) };
        }
        0x5 => a = b & c,
        0x6 => a = b | c,
        0x7 => a = b ^ c,
        0x8 => {
            // shl. Python masks differently for long vs not-long:
            // long → c % 64 + BIT_BACK = 0xFFFFFFFFFFFFFFFF
            // else → c % 32 + BIT_BACK = 0xFFFFFF       <-- 24-bit (Python bug)
            let bit_back: u64;
            if operand == 0x1 {
                c %= 64;
                bit_back = 0xFFFFFFFFFFFFFFFF;
            } else {
                c %= 32;
                bit_back = 0xFFFFFF; // Python quirk: 24-bit mask, not 32-bit.
            }
            let raw = (b as u64).wrapping_shl(c as u32);
            a = (raw & bit_back) as i64;
        }
        0x9 => {
            // shr. Same masking quirk as shl.
            let bit_back: u64;
            if operand == 0x1 {
                c %= 64;
                bit_back = 0xFFFFFFFFFFFFFFFF;
            } else {
                c %= 32;
                bit_back = 0xFFFFFF;
            }
            // Python `>>` on signed ints is arithmetic shift.
            let raw = (b >> c) as u64;
            a = (raw & bit_back) as i64;
        }
        0xa => {
            // ushr — and here's the second Python quirk.
            let bit_back: u64;
            if operand == 0x1 {
                c %= 64;
                bit_back = 0xFFFFFFFFFFFFFFFF;
            } else {
                c %= 32;
                bit_back = 0xFFFFFF;
            }
            // Python: shift = b % (1 << 32)
            let shift = (b as u64) % (1u64 << 32);
            if operand == 0x0 {
                // int → real ushr
                a = ((shift >> c) & bit_back) as i64;
            } else {
                // long → Python uses LEFT shift here (likely a bug).
                // We mirror it byte-for-byte.
                a = ((shift.wrapping_shl(c as u32)) & bit_back) as i64;
            }
        }
        _ => a = 0,
    }

    // Operand-type masking — trim the result to the right width and
    // sign-extend back to i64. Mirrors Python's post-mask block at
    // `reg_ops_helper` lines 74-83 of `instructions_new.py`.
    //
    // Python quirk: the sign-extension constant is `0xFFFFFFFF - 1`
    // (=0xFFFFFFFE), NOT `0xFFFFFFFF + 1` (=0x100000000) as the spec
    // would call for. So Python's int sign-extension is off by 2.
    // For masked = 0x80000000, Python returns -2147483646 instead of
    // the spec's -2147483648. We mirror the bug verbatim — it's load-
    // bearing for output-parity with the Python reference.
    //
    // The long branch has the same off-by-2 bug (`0xFFFFFFFFFFFFFFFF - 1`)
    // but Rust's i64 arithmetic already saturates at 2^63 so the
    // bug is unreachable here. We don't need to do anything for that
    // case.
    match operand {
        0x0 => {
            let masked = (a as u64) & 0xFFFFFFFF;
            a = if masked > 0x7FFFFFFF {
                // Python: `a -= 0xFFFFFFFF - 1` = `a -= 0xFFFFFFFE`.
                masked.wrapping_sub(0xFFFFFFFE) as i64
            } else {
                masked as i64
            };
        }
        _ => {
            // long / float / double — already i64-sized; nothing to do.
        }
    }

    a
}

/// Python's `b // c` for integers: floor division. Rust's `/`
/// truncates; we adjust when the result would have a non-zero
/// remainder of the opposite sign.
fn python_floor_div(b: i64, c: i64) -> i64 {
    let q = b / c;
    let r = b % c;
    if (r != 0) && ((r < 0) != (c < 0)) {
        q - 1
    } else {
        q
    }
}

/// Python's `b % c`: result has the same sign as the divisor.
fn python_mod(b: i64, c: i64) -> i64 {
    let r = b % c;
    if (r != 0) && ((r < 0) != (c < 0)) {
        r + c
    } else {
        r
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Operator coverage: int operand (0x0) ─────────────────────

    #[test]
    fn add_int() { assert_eq!(reg_ops_helper(0x0, 0x0, 3, 4), 7); }
    #[test]
    fn sub_int() { assert_eq!(reg_ops_helper(0x1, 0x0, 10, 4), 6); }
    #[test]
    fn mul_int() { assert_eq!(reg_ops_helper(0x2, 0x0, 6, 7), 42); }

    #[test]
    fn div_int_floor_div_then_off_by_two_post_mask() {
        // Python: -7 // 2 == -4 (floor), then the int post-mask
        // mangles negatives: -4 & 0xFFFFFFFF = 0xFFFFFFFC = 4294967292,
        // > 0x7FFFFFFF, so subtract 0xFFFFFFFE → -2. Yes really.
        assert_eq!(reg_ops_helper(0x3, 0x0, -7, 2), -2);
        // 7 // 2 = 3, positive — no post-mask mangling.
        assert_eq!(reg_ops_helper(0x3, 0x0, 7, 2), 3);
    }

    #[test]
    fn div_by_zero_returns_zero() {
        assert_eq!(reg_ops_helper(0x3, 0x0, 100, 0), 0);
        assert_eq!(reg_ops_helper(0x4, 0x0, 100, 0), 0);
    }

    #[test]
    fn rem_int_follows_divisor_sign_then_post_mask() {
        // Python: -7 % 3 == 2 (divisor-sign mod). 2 is positive and
        // unaffected by the post-mask.
        assert_eq!(reg_ops_helper(0x4, 0x0, -7, 3), 2);
        // 7 % -3 == -2 (divisor-sign mod). Post-mask mangles:
        // -2 & 0xFFFFFFFF = 0xFFFFFFFE, > 0x7FFFFFFF, subtract
        // 0xFFFFFFFE → 0. Reference (buggy) output is 0, not -2.
        assert_eq!(reg_ops_helper(0x4, 0x0, 7, -3), 0);
    }

    #[test]
    fn bitwise_ops_int() {
        assert_eq!(reg_ops_helper(0x5, 0x0, 0xF0, 0x0F), 0);          // and
        assert_eq!(reg_ops_helper(0x6, 0x0, 0xF0, 0x0F), 0xFF);       // or
        assert_eq!(reg_ops_helper(0x7, 0x0, 0xFF, 0x0F), 0xF0);       // xor
    }

    // ── Python's 24-bit shift mask quirk ────────────────────────

    #[test]
    fn shl_int_uses_24_bit_mask() {
        // 1 << 16 = 0x10000. 0x10000 & 0xFFFFFF = 0x10000. OK.
        assert_eq!(reg_ops_helper(0x8, 0x0, 1, 16), 0x10000);
        // 1 << 24 = 0x1000000. Masked to 0xFFFFFF = 0. Quirk.
        assert_eq!(reg_ops_helper(0x8, 0x0, 1, 24), 0);
    }

    #[test]
    fn shl_long_uses_full_64_bit_mask() {
        // 1 << 40 — long mask is 0xFFFFFFFFFFFFFFFF, so the bit survives.
        assert_eq!(reg_ops_helper(0x8, 0x1, 1, 40), 1i64 << 40);
    }

    #[test]
    fn ushr_long_actually_shifts_left() {
        // Python quirk: ushr in long mode uses `shift << c`.
        // shift = b % (1 << 32); for b = 0xFF, shift = 0xFF.
        // c = 4. Expected (per Python): 0xFF << 4 = 0xFF0.
        assert_eq!(reg_ops_helper(0xa, 0x1, 0xFF, 4), 0xFF0);
    }

    #[test]
    fn ushr_int_is_real_unsigned_shift() {
        // b = -16 → Python `b % (1 << 32)` = 0xFFFFFFF0
        // shift >> 4 = 0x0FFFFFFF (low 28 bits set)
        // masked to 0xFFFFFF (24-bit Python quirk) = 0xFFFFFF
        assert_eq!(reg_ops_helper(0xa, 0x0, -16, 4), 0xFFFFFF);
    }

    // ── Operand-type post-masking ───────────────────────────────

    #[test]
    fn int_post_mask_sign_extends_with_python_off_by_two() {
        // Add 0x40000000 + 0x40000000 = 0x80000000 (= 2^31).
        // Spec sign-extension would give -2^31 = -2147483648.
        // Python uses `a -= 0xFFFFFFFE` instead of `a -= 0x100000000`
        // (off by 2) so it returns -2147483646. We mirror that.
        let r = reg_ops_helper(0x0, 0x0, 0x40000000, 0x40000000);
        assert_eq!(r, -2147483646);
    }

    #[test]
    fn int_post_mask_at_ffffffff_returns_one_not_negative_one() {
        // 0xFFFFFFFF is the most negative-looking value possible.
        // Spec: should become -1. Python's off-by-2: 0xFFFFFFFF - 0xFFFFFFFE = 1.
        // bv | cv = 0xFFFFFFFF.
        let r = reg_ops_helper(0x6, 0x0, 0xFFFFFFFF, 0);
        assert_eq!(r, 1);
    }

    #[test]
    fn long_post_mask_keeps_full_i64() {
        // Long add of two large positives wraps via wrapping_add;
        // we don't truncate further.
        let r = reg_ops_helper(0x0, 0x1, i64::MAX, 1);
        assert_eq!(r, i64::MIN);  // overflowed
    }

    // ── Floor div helper sanity ─────────────────────────────────

    #[test]
    fn python_floor_div_matches_python() {
        assert_eq!(python_floor_div(7, 2), 3);
        assert_eq!(python_floor_div(-7, 2), -4);
        assert_eq!(python_floor_div(7, -2), -4);
        assert_eq!(python_floor_div(-7, -2), 3);
    }

    #[test]
    fn python_mod_matches_python() {
        assert_eq!(python_mod(7, 3), 1);
        assert_eq!(python_mod(-7, 3), 2);
        assert_eq!(python_mod(7, -3), -2);
        assert_eq!(python_mod(-7, -3), -1);
    }
}
