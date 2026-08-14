/// Utility functions — translates dex/helpers.py

/// Convert little-endian bytes to u64.
/// Equivalent to Python's `b2i` (int.from_bytes(raw_bytes, "little")).
pub fn b2i(bytes: &[u8]) -> u64 {
    let mut result = 0u64;
    for (i, &b) in bytes.iter().enumerate() {
        result |= (b as u64) << (i * 8);
    }
    result
}

/// Return the low nibble of a byte.
pub fn lsb(b: u8) -> u8 {
    b & 0x0F
}

/// Return the high nibble of a byte.
pub fn msb(b: u8) -> u8 {
    b >> 4
}

/// Return the nibble at position `idx` (0 = least significant).
pub fn nibble_at(value: u64, idx: u32) -> u8 {
    ((value >> (4 * idx)) & 0x0F) as u8
}

/// Two's complement interpretation of `number` as a `num_bytes`-byte signed integer.
pub fn twos_complement(number: i64, num_bytes: u32) -> i64 {
    let bits = num_bytes * 8;
    if (number >> (bits - 1)) & 1 == 1 {
        number - (1i64 << bits)
    } else {
        number
    }
}

/// Sign-extend `value` from `bits` wide to a full i64.
/// Equivalent to Python's `sign_extend`.
pub fn sign_extend(value: i64, bits: u32) -> i64 {
    let sign_bit = 1i64 << (bits - 1);
    (value & (sign_bit - 1)) - (value & sign_bit)
}

/// Logical (unsigned) right shift — treats `signed_integer` as `num_bits`-wide unsigned.
pub fn logical_rshift(signed_integer: i64, places: u32, num_bits: u32) -> i64 {
    let unsigned = (signed_integer as u64) & (!0u64 >> (64 - num_bits));
    (unsigned >> places) as i64
}

/// Logical (unsigned) left shift.
pub fn logical_lshift(signed_integer: i64, places: u32, num_bits: u32) -> i64 {
    let unsigned = (signed_integer as u64) & (!0u64 >> (64 - num_bits));
    (unsigned << places) as i64
}

/// ALU operation matching helpers.py `alu_op`.
///
/// `op`:
///   0=add, 1=sub, 2=mul, 3=div, 4=rem, 5=and, 6=or, 7=xor, 8=shl, 9=shr, 10=ushr
///
/// `operand`:
///   0=int (32-bit), 1=long (64-bit), 2=float, 3=double
pub fn alu_op(op: u8, operand: u8, b: i64, c: i64) -> i64 {
    let mut a: i64 = match op {
        0 => b.wrapping_add(c),
        1 => b.wrapping_sub(c),
        2 => b.wrapping_mul(c),
        3 => {
            if c == 0 { 0 } else { b.wrapping_div(c) }
        }
        4 => {
            if c == 0 { 0 } else { b.wrapping_rem(c) }
        }
        5 => b & c,
        6 => b | c,
        7 => b ^ c,
        8 => {
            // shl
            if operand == 1 {
                let shift = (c % 64) as u32;
                let mask = 0xFFFFFFFFFFFFFFFFu64;
                ((b as u64) << shift & mask) as i64
            } else {
                let shift = (c % 32) as u32;
                let mask = 0xFFFFFFFFu64;
                ((b as u64) << shift & mask) as i64
            }
        }
        9 => {
            // shr (arithmetic)
            if operand == 1 {
                let shift = (c % 64) as u32;
                b >> shift
            } else {
                let shift = (c % 32) as u32;
                (b as i32 >> shift) as i64
            }
        }
        10 => {
            // ushr (logical)
            if operand == 1 {
                let shift = (c % 64) as u32;
                logical_rshift(b, shift, 64)
            } else {
                let shift = (c % 32) as u32;
                logical_rshift(b, shift, 32)
            }
        }
        _ => 0,
    };

    // Re-apply integer bounds
    a = match operand {
        0 => {
            // int (32-bit signed)
            let v = a as i32;
            v as i64
        }
        1 => {
            // long (64-bit signed) — already i64
            a
        }
        _ => a,
    };

    a
}

/// Java-style String.hashCode().
/// From helpers.py `string_hash_code`.
pub fn string_hash_code(s: &str) -> i32 {
    let mut h: i32 = 0;
    for c in s.chars() {
        h = (31i32.wrapping_mul(h)).wrapping_add(c as i32);
    }
    h
}
