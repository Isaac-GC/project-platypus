/// Opcode width table and branch helpers — translates codegen/opcode_helper.py

use crate::helpers::sign_extend;

/// Returns the width (in code units) of a Dalvik opcode.
/// A "code unit" is 2 bytes.
pub fn get_opcode_width(opcode: u8) -> Option<u32> {
    Some(match opcode {
        // ── 1 code unit ──────────────────────────────────────────────────────
        0x00 => 1, // nop
        0x0e => 1, // return-void
        0x28 => 1, // goto
        0x0a => 1, // move-result
        0x0b => 1, // move-result-wide
        0x0c => 1, // move-result-object
        0x0d => 1, // move-exception
        0x0f => 1, // return
        0x10 => 1, // return-wide
        0x11 => 1, // return-object
        0x1d => 1, // monitor-enter
        0x1e => 1, // monitor-exit
        0x27 => 1, // throw
        0x12 => 1, // const/4
        0x01 => 1, // move
        0x04 => 1, // move-wide
        0x07 => 1, // move-object
        0x21 => 1, // array-length
        0x7b => 1, // neg-int
        0x7c => 1, // not-int
        0x7d => 1, // neg-long
        0x7e => 1, // not-long
        0x7f => 1, // neg-float
        0x80 => 1, // neg-double
        0x81 => 1, // int-to-long
        0x82 => 1, // int-to-float
        0x83 => 1, // int-to-double
        0x84 => 1, // long-to-int
        0x85 => 1, // long-to-float
        0x86 => 1, // long-to-double
        0x87 => 1, // float-to-int
        0x88 => 1, // float-to-long
        0x89 => 1, // float-to-double
        0x8a => 1, // double-to-int
        0x8b => 1, // double-to-long
        0x8c => 1, // double-to-float
        0x8d => 1, // int-to-byte
        0x8e => 1, // int-to-char
        0x8f => 1, // int-to-short
        0xb0 => 1, // add-int/2addr
        0xb1 => 1, // sub-int/2addr
        0xb2 => 1, // mul-int/2addr
        0xb3 => 1, // div-int/2addr
        0xb4 => 1, // rem-int/2addr
        0xb5 => 1, // and-int/2addr
        0xb6 => 1, // or-int/2addr
        0xb7 => 1, // xor-int/2addr
        0xb8 => 1, // shl-int/2addr
        0xb9 => 1, // shr-int/2addr
        0xba => 1, // ushr-int/2addr
        0xbb => 1, // add-long/2addr
        0xbc => 1, // sub-long/2addr
        0xbd => 1, // mul-long/2addr
        0xbe => 1, // div-long/2addr
        0xbf => 1, // rem-long/2addr
        0xc0 => 1, // and-long/2addr
        0xc1 => 1, // or-long/2addr
        0xc2 => 1, // xor-long/2addr
        0xc3 => 1, // shl-long/2addr
        0xc4 => 1, // shr-long/2addr
        0xc5 => 1, // ushr-long/2addr
        0xc6 => 1, // add-float/2addr
        0xc7 => 1, // sub-float/2addr
        0xc8 => 1, // mul-float/2addr
        0xc9 => 1, // div-float/2addr
        0xca => 1, // rem-float/2addr
        0xcb => 1, // add-double/2addr
        0xcc => 1, // sub-double/2addr
        0xcd => 1, // mul-double/2addr
        0xce => 1, // div-double/2addr
        0xcf => 1, // rem-double/2addr

        // ── 2 code units ─────────────────────────────────────────────────────
        0x29 => 2, // goto/16
        0x1a => 2, // const-string
        0x1c => 2, // const-class
        0x1f => 2, // check-cast
        0x22 => 2, // new-instance
        0x60 => 2, // sget
        0x61 => 2, // sget-wide
        0x62 => 2, // sget-object
        0x63 => 2, // sget-boolean
        0x64 => 2, // sget-byte
        0x65 => 2, // sget-char
        0x66 => 2, // sget-short
        0x67 => 2, // sput
        0x68 => 2, // sput-wide
        0x69 => 2, // sput-object
        0x6a => 2, // sput-boolean
        0x6b => 2, // sput-byte
        0x6c => 2, // sput-char
        0x6d => 2, // sput-short
        0xfe => 2, // const-method-handle (DEX 039+)
        0xff => 2, // const-method-type   (DEX 039+)
        0x15 => 2, // const/high16
        0x19 => 2, // const-wide/high16
        0x13 => 2, // const/16
        0x16 => 2, // const-wide/16
        0x38 => 2, // if-eqz
        0x39 => 2, // if-nez
        0x3a => 2, // if-ltz
        0x3b => 2, // if-gez
        0x3c => 2, // if-gtz
        0x3d => 2, // if-lez
        0xd0 => 2, // add-int/lit16
        0xd1 => 2, // rsub-int
        0xd2 => 2, // mul-int/lit16
        0xd3 => 2, // div-int/lit16
        0xd4 => 2, // rem-int/lit16
        0xd5 => 2, // and-int/lit16
        0xd6 => 2, // or-int/lit16
        0xd7 => 2, // xor-int/lit16
        0x20 => 2, // instance-of
        0x23 => 2, // new-array
        0x52 => 2, // iget
        0x53 => 2, // iget-wide
        0x54 => 2, // iget-object
        0x55 => 2, // iget-boolean
        0x56 => 2, // iget-byte
        0x57 => 2, // iget-char
        0x58 => 2, // iget-short
        0x59 => 2, // iput
        0x5a => 2, // iput-wide
        0x5b => 2, // iput-object
        0x5c => 2, // iput-boolean
        0x5d => 2, // iput-byte
        0x5e => 2, // iput-char
        0x5f => 2, // iput-short
        0xd8 => 2, // add-int/lit8
        0xd9 => 2, // rsub-int/lit8
        0xda => 2, // mul-int/lit8
        0xdb => 2, // div-int/lit8
        0xdc => 2, // rem-int/lit8
        0xdd => 2, // and-int/lit8
        0xde => 2, // or-int/lit8
        0xdf => 2, // xor-int/lit8
        0xe0 => 2, // shl-int/lit8
        0xe1 => 2, // shr-int/lit8
        0xe2 => 2, // ushr-int/lit8
        0x32 => 2, // if-eq
        0x33 => 2, // if-ne
        0x34 => 2, // if-lt
        0x35 => 2, // if-ge
        0x36 => 2, // if-gt
        0x37 => 2, // if-le
        0x02 => 2, // move/from16
        0x05 => 2, // move-wide/from16
        0x08 => 2, // move-object/from16
        0x2d => 2, // cmpl-float
        0x2e => 2, // cmpg-float
        0x2f => 2, // cmpl-double
        0x30 => 2, // cmpg-double
        0x31 => 2, // cmp-long
        0x44 => 2, // aget
        0x45 => 2, // aget-wide
        0x46 => 2, // aget-object
        0x47 => 2, // aget-boolean
        0x48 => 2, // aget-byte
        0x49 => 2, // aget-char
        0x4a => 2, // aget-short
        0x4b => 2, // aput
        0x4c => 2, // aput-wide
        0x4d => 2, // aput-object
        0x4e => 2, // aput-boolean
        0x4f => 2, // aput-byte
        0x50 => 2, // aput-char
        0x51 => 2, // aput-short
        0x90 => 2, // add-int
        0x91 => 2, // sub-int
        0x92 => 2, // mul-int
        0x93 => 2, // div-int
        0x94 => 2, // rem-int
        0x95 => 2, // and-int
        0x96 => 2, // or-int
        0x97 => 2, // xor-int
        0x98 => 2, // shl-int
        0x99 => 2, // shr-int
        0x9a => 2, // ushr-int
        0x9b => 2, // add-long
        0x9c => 2, // sub-long
        0x9d => 2, // mul-long
        0x9e => 2, // div-long
        0x9f => 2, // rem-long
        0xa0 => 2, // and-long
        0xa1 => 2, // or-long
        0xa2 => 2, // xor-long
        0xa3 => 2, // shl-long
        0xa4 => 2, // shr-long
        0xa5 => 2, // ushr-long
        0xa6 => 2, // add-float
        0xa7 => 2, // sub-float
        0xa8 => 2, // mul-float
        0xa9 => 2, // div-float
        0xaa => 2, // rem-float
        0xab => 2, // add-double
        0xac => 2, // sub-double
        0xad => 2, // mul-double
        0xae => 2, // div-double
        0xaf => 2, // rem-double

        // ── 3 code units ─────────────────────────────────────────────────────
        0x2a => 3, // goto/32
        0x1b => 3, // const-string/jumbo
        0x14 => 3, // const
        0x17 => 3, // const-wide/32
        0x26 => 3, // fill-array-data
        0x2b => 3, // packed-switch
        0x2c => 3, // sparse-switch
        0x03 => 3, // move/16
        0x06 => 3, // move-wide/16
        0x09 => 3, // move-object/16
        0x24 => 3, // filled-new-array
        0x6e => 3, // invoke-virtual
        0x6f => 3, // invoke-super
        0x70 => 3, // invoke-direct
        0x71 => 3, // invoke-static
        0x72 => 3, // invoke-interface
        0x25 => 3, // filled-new-array/range
        0x74 => 3, // invoke-virtual/range
        0x75 => 3, // invoke-super/range
        0x76 => 3, // invoke-direct/range
        0x77 => 3, // invoke-static/range
        0x78 => 3, // invoke-interface/range
        0xfc => 3, // invoke-custom
        0xfd => 3, // invoke-custom/range

        // ── 4 code units ─────────────────────────────────────────────────────
        0xfa => 4, // invoke-polymorphic
        0xfb => 4, // invoke-polymorphic/range

        // ── 5 code units ─────────────────────────────────────────────────────
        0x18 => 5, // const-wide

        _ => return None,
    })
}

/// Number of bits in the branch offset field for branch/switch instructions.
pub fn branch_offset_bits(opcode: u8) -> Option<u32> {
    match opcode {
        0x28 => Some(8),
        0x29 => Some(16),
        0x2a => Some(32),
        0x32..=0x37 => Some(16), // if-eq .. if-le
        0x38..=0x3d => Some(16), // if-eqz .. if-lez
        0x2b | 0x2c => Some(32), // packed-switch / sparse-switch
        0x26 => Some(32),        // fill-array-data
        _ => None,
    }
}

/// Which operand index (0-based) holds the branch offset.
pub fn branch_offset_operand_index(opcode: u8) -> Option<usize> {
    match opcode {
        0x28 | 0x29 | 0x2a => Some(0),        // goto family: operands[0]
        0x38..=0x3d => Some(1),                // if-*z: operands[1]
        0x32..=0x37 => Some(2),                // if-*: operands[2]
        0x2b | 0x2c | 0x26 => Some(1),         // switch/array: operands[1]
        _ => None,
    }
}

/// Resolve the absolute branch target codepoint for a branch instruction.
/// `codepoint` is the instruction's own codepoint; `raw_offset` is the signed offset field.
pub fn resolve_branch_target(opcode: u8, codepoint: i64, raw_offset: i64) -> Option<i64> {
    let bits = branch_offset_bits(opcode)?;
    let signed_offset = sign_extend(raw_offset, bits);
    Some(codepoint + signed_offset)
}
