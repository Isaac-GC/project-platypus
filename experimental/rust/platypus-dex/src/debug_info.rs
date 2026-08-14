/// DEX debug_info_item parser — produces a codepoint → source line table.
///
/// Implements the DEX debug info state machine as specified in
/// the Dalvik Executable Format documentation.

// ── ULEB128 / SLEB128 helpers ────────────────────────────────────────────────

fn read_uleb128(data: &[u8], pos: &mut usize) -> u32 {
    let mut result: u32 = 0;
    let mut shift: u32 = 0;
    loop {
        if *pos >= data.len() { break; }
        let b = data[*pos];
        *pos += 1;
        result |= ((b & 0x7f) as u32) << shift;
        shift += 7;
        if b & 0x80 == 0 { break; }
    }
    result
}

fn read_sleb128(data: &[u8], pos: &mut usize) -> i32 {
    let mut result: i32 = 0;
    let mut shift: u32 = 0;
    let mut last_b: u8 = 0;
    loop {
        if *pos >= data.len() { break; }
        let b = data[*pos];
        *pos += 1;
        result |= ((b & 0x7f) as i32) << shift;
        shift += 7;
        last_b = b;
        if b & 0x80 == 0 { break; }
    }
    // sign extend
    if shift < 32 && (last_b & 0x40) != 0 {
        result |= !0i32 << shift;
    }
    result
}

// ── Debug info opcode constants ───────────────────────────────────────────────

const DBG_END_SEQUENCE:         u8 = 0x00;
const DBG_ADVANCE_PC:           u8 = 0x01;
const DBG_ADVANCE_LINE:         u8 = 0x02;
const DBG_START_LOCAL:          u8 = 0x03;
const DBG_START_LOCAL_EXTENDED: u8 = 0x04;
const DBG_END_LOCAL:            u8 = 0x05;
const DBG_RESTART_LOCAL:        u8 = 0x06;
const DBG_SET_PROLOGUE_END:     u8 = 0x07;
const DBG_SET_EPILOGUE_BEGIN:   u8 = 0x08;
const DBG_SET_FILE:             u8 = 0x09;
const DBG_FIRST_SPECIAL:        u8 = 0x0a;

const DBG_LINE_BASE:   i32 = -4;
const DBG_LINE_RANGE:  u8  = 15;

// ── Public API ────────────────────────────────────────────────────────────────

/// Parse a DEX debug_info_item starting at `offset` in `data`.
/// Returns a sorted `Vec<(codepoint, line)>` that can be binary-searched.
pub fn parse_line_table(data: &[u8], offset: usize) -> Vec<(u32, u32)> {
    if offset == 0 || offset >= data.len() {
        return Vec::new();
    }

    let mut pos = offset;

    // line_start: initial value of the line register
    let line_start = read_uleb128(data, &mut pos);
    // parameters_size: number of parameter names to skip
    let parameters_size = read_uleb128(data, &mut pos);
    for _ in 0..parameters_size {
        // each is uleb128p1 (string index + 1, 0 = no name)
        let _name_idx = read_uleb128(data, &mut pos);
    }

    let mut pc: u32   = 0;
    let mut line: i32 = line_start as i32;
    let mut table: Vec<(u32, u32)> = Vec::new();

    loop {
        if pos >= data.len() { break; }
        let opcode = data[pos];
        pos += 1;

        match opcode {
            DBG_END_SEQUENCE => break,

            DBG_ADVANCE_PC => {
                let addr_diff = read_uleb128(data, &mut pos);
                pc += addr_diff;
            }

            DBG_ADVANCE_LINE => {
                let line_diff = read_sleb128(data, &mut pos);
                line += line_diff;
            }

            DBG_START_LOCAL => {
                let _register   = read_uleb128(data, &mut pos);
                let _name_idx   = read_uleb128(data, &mut pos); // uleb128p1
                let _type_idx   = read_uleb128(data, &mut pos); // uleb128p1
            }

            DBG_START_LOCAL_EXTENDED => {
                let _register   = read_uleb128(data, &mut pos);
                let _name_idx   = read_uleb128(data, &mut pos);
                let _type_idx   = read_uleb128(data, &mut pos);
                let _sig_idx    = read_uleb128(data, &mut pos);
            }

            DBG_END_LOCAL | DBG_RESTART_LOCAL => {
                let _register = read_uleb128(data, &mut pos);
            }

            DBG_SET_PROLOGUE_END | DBG_SET_EPILOGUE_BEGIN => {
                // no operand
            }

            DBG_SET_FILE => {
                let _name_idx = read_uleb128(data, &mut pos); // uleb128p1
            }

            special => {
                // special opcodes: 0x0a .. 0xff
                let adjusted  = (special - DBG_FIRST_SPECIAL) as i32;
                let line_delta = DBG_LINE_BASE + (adjusted % DBG_LINE_RANGE as i32);
                let addr_delta = (adjusted / DBG_LINE_RANGE as i32) as u32;
                pc   += addr_delta;
                line += line_delta;
                if line > 0 {
                    table.push((pc, line as u32));
                }
            }
        }
    }

    // table should already be sorted by pc since pc only increases,
    // but sort anyway to be safe.
    table.sort_unstable_by_key(|&(cp, _)| cp);
    table
}

/// Look up the source line for a given codepoint.
/// Returns the line number of the last entry whose codepoint <= `cp`.
pub fn lookup_line(table: &[(u32, u32)], cp: u32) -> Option<u32> {
    if table.is_empty() { return None; }
    // Binary search for the last entry with codepoint <= cp
    let idx = table.partition_point(|&(entry_cp, _)| entry_cp <= cp);
    if idx == 0 { return None; }
    Some(table[idx - 1].1)
}
