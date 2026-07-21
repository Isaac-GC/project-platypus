/// Dalvik instruction decoder — translates dex/instructions_new.py
///
/// Each instruction is represented as a flat `Instruction` struct (common
/// fields) plus an `InstructionKind` enum that carries type-specific data.
/// The `decode` free function dispatches on the opcode and fills both.

use std::collections::HashMap;
use super::parser::ParsedDex;
use crate::opcode_helper::get_opcode_width;

// ── Control flow classification ───────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlFlow {
    Terminate,
    GoTo,
    Branch,
    FallThrough,
}

// ── Switch-table payloads ────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct SwitchTable {
    /// Maps integer key → relative branch offset (relative to the Switch instruction's codepoint).
    pub table: HashMap<i32, i32>,
}

// ── Instruction kind ──────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum InstructionKind {
    Nop,
    PackedSwitchPayload { size: u16, first_key: i32, targets: Vec<i32> },
    SparseSwitchPayload { size: u16, keys: Vec<i32>, targets: Vec<i32> },
    FillArrayDataPayload { element_width: u16, element_count: u32, data: Vec<u8> },
    Move,
    MoveResult,
    Return,
    Const,
    Monitor,
    CheckCast,
    InstanceOf,
    ArrLength,
    NewInstance,
    Array,
    Throw,
    Goto,
    Switch { table: SwitchTable },
    Cmp,
    If,
    IfZ,
    ArrayOp,
    IGet,
    IPut,
    SGet,
    SPut,
    InvokeKind,
    InvokeKindRange,
    UnOp,
    BinOp   { operator_type: u8, operand_type: u8 },
    BinOp2Addr { operator_type: u8, operand_type: u8 },
    BinOpLit { operator_type: u8 },
    InvokePolymorphic,
    InvokeCustom,
    Unknown,
}

// ── Flat instruction struct ───────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct Instruction {
    pub opcode: u8,
    /// Address (byte offset) at decode time.
    pub address: u64,
    /// Codepoint (index in code units, not bytes).
    pub codepoint: u32,
    /// Instruction format string (e.g. "12x", "35c").
    pub fmt: &'static str,
    /// Human-readable disassembly string.
    pub instruction_str: String,
    /// Instruction width in code units.
    pub width: u32,
    pub control_flow: ControlFlow,
    pub kind: InstructionKind,

    // Register operands (None if not used by this format)
    pub v_a: Option<i64>,
    pub v_b: Option<i64>,
    pub v_c: Option<i64>,
    pub v_d: Option<i64>,
    pub v_e: Option<i64>,
    pub v_f: Option<i64>,
    pub v_g: Option<i64>,
    pub v_h: Option<i64>,
    pub v_z: Option<i64>, // padding / unused byte

    /// All non-None operands in order [A, B, C, D, E, F, G, H].
    pub operands: Vec<i64>,
}

impl Instruction {
    fn new(opcode: u8, width: u32) -> Self {
        Instruction {
            opcode,
            address: 0,
            codepoint: 0,
            fmt: "10x",
            instruction_str: String::new(),
            width,
            control_flow: ControlFlow::FallThrough,
            kind: InstructionKind::Unknown,
            v_a: None, v_b: None, v_c: None, v_d: None,
            v_e: None, v_f: None, v_g: None, v_h: None,
            v_z: None,
            operands: Vec::new(),
        }
    }

    fn build_operands(&mut self) {
        self.operands = [
            self.v_a, self.v_b, self.v_c, self.v_d,
            self.v_e, self.v_f, self.v_g, self.v_h,
        ]
        .iter()
        .filter_map(|&v| v)
        .collect();
    }
}

// ── Low-level format readers ──────────────────────────────────────────────────

struct FmtReader<'a> {
    buf: &'a [u8],
    /// Position within `buf`, in bytes, starting after the opcode byte.
    pos: usize,
}

impl<'a> FmtReader<'a> {
    fn new(buf: &'a [u8]) -> Self { FmtReader { buf, pos: 0 } }

    fn read_u8(&mut self) -> i64 {
        let v = self.buf[self.pos];
        self.pos += 1;
        v as i64
    }
    fn read_i8(&mut self) -> i64 {
        let v = self.buf[self.pos] as i8;
        self.pos += 1;
        v as i64
    }
    fn read_u16_le(&mut self) -> i64 {
        let v = u16::from_le_bytes([self.buf[self.pos], self.buf[self.pos+1]]);
        self.pos += 2;
        v as i64
    }
    fn read_i16_le(&mut self) -> i64 {
        let v = i16::from_le_bytes([self.buf[self.pos], self.buf[self.pos+1]]);
        self.pos += 2;
        v as i64
    }
    fn read_u32_le(&mut self) -> i64 {
        let v = u32::from_le_bytes([
            self.buf[self.pos], self.buf[self.pos+1],
            self.buf[self.pos+2], self.buf[self.pos+3],
        ]);
        self.pos += 4;
        v as i64
    }
    fn read_i32_le(&mut self) -> i64 {
        let v = i32::from_le_bytes([
            self.buf[self.pos], self.buf[self.pos+1],
            self.buf[self.pos+2], self.buf[self.pos+3],
        ]);
        self.pos += 4;
        v as i64
    }
    fn read_i64_le(&mut self) -> i64 {
        let v = i64::from_le_bytes(self.buf[self.pos..self.pos+8].try_into().unwrap());
        self.pos += 8;
        v
    }
    fn nibbles(&mut self) -> (i64, i64) {
        let b = self.buf[self.pos];
        self.pos += 1;
        ((b & 0x0F) as i64, (b >> 4) as i64)
    }
}

/// Decode format arguments from `payload` (bytes after opcode) into `instr`.
fn decode_args(instr: &mut Instruction, payload: &[u8]) {
    let mut r = FmtReader::new(payload);
    match instr.fmt {
        "10t" => {
            instr.v_a = Some(r.read_i8());
        }
        "10x" => {
            instr.v_z = Some(r.read_u8());
        }
        "11n" => {
            let (lo, hi) = r.nibbles();
            instr.v_a = Some(lo);
            instr.v_b = Some(if hi < 8 { hi } else { hi - 16 });
        }
        "11x" => {
            instr.v_a = Some(r.read_u8());
        }
        "12x" => {
            let (lo, hi) = r.nibbles();
            instr.v_a = Some(lo);
            instr.v_b = Some(hi);
        }
        "20t" => {
            let _ = r.read_u8(); // padding
            instr.v_a = Some(r.read_i16_le());
        }
        "21c" | "22x" => {
            instr.v_a = Some(r.read_u8());
            instr.v_b = Some(r.read_u16_le());
        }
        "21h" | "21s" | "21t" => {
            instr.v_a = Some(r.read_u8());
            instr.v_b = Some(r.read_i16_le());
        }
        "22b" => {
            instr.v_a = Some(r.read_u8());
            instr.v_b = Some(r.read_u8());
            instr.v_c = Some(r.read_i8());
        }
        "22c" => {
            let (lo, hi) = r.nibbles();
            instr.v_a = Some(lo);
            instr.v_b = Some(hi);
            instr.v_c = Some(r.read_u16_le());
        }
        "22s" | "22t" => {
            let (lo, hi) = r.nibbles();
            instr.v_a = Some(lo);
            instr.v_b = Some(hi);
            instr.v_c = Some(r.read_i16_le());
        }
        "23x" => {
            instr.v_a = Some(r.read_u8());
            instr.v_b = Some(r.read_u8());
            instr.v_c = Some(r.read_u8());
        }
        "30t" => {
            let _ = r.read_u8(); // padding
            instr.v_a = Some(r.read_i32_le());
        }
        "31i" | "31t" => {
            instr.v_a = Some(r.read_u8());
            instr.v_b = Some(r.read_i32_le());
        }
        "31c" => {
            instr.v_a = Some(r.read_u8());
            instr.v_b = Some(r.read_u32_le());
        }
        "32x" => {
            let _ = r.read_u8(); // padding
            instr.v_a = Some(r.read_u16_le());
            instr.v_b = Some(r.read_u16_le());
        }
        "35c" => {
            let (vg, va) = r.nibbles(); // vA = count, vG = last register
            instr.v_a = Some(va);
            instr.v_g = Some(vg);
            instr.v_b = Some(r.read_u16_le()); // method/type index
            let (vc, vd) = r.nibbles();
            let (ve, vf) = r.nibbles();
            instr.v_c = Some(vc);
            instr.v_d = Some(vd);
            instr.v_e = Some(ve);
            instr.v_f = Some(vf);
        }
        "3rc" => {
            instr.v_a = Some(r.read_u8());
            instr.v_b = Some(r.read_u16_le());
            instr.v_c = Some(r.read_u16_le());
        }
        "51l" => {
            instr.v_a = Some(r.read_u8());
            instr.v_b = Some(r.read_i64_le());
        }
        _ => {}
    }
}

// ── Helpers for safe table lookups ────────────────────────────────────────────

fn safe_string(dex: &ParsedDex, idx: i64) -> String {
    dex.strings.get(idx as usize)
        .map(|s| s.data.clone())
        .unwrap_or_else(|| format!("string@{}", idx))
}

fn safe_type(dex: &ParsedDex, idx: i64) -> String {
    dex.type_ids.get(idx as usize)
        .map(|t| t.type_name.clone())
        .unwrap_or_else(|| format!("type@{}", idx))
}

fn safe_field(dex: &ParsedDex, idx: i64) -> String {
    dex.field_ids.get(idx as usize)
        .map(|f| format!("{}->{}: {}", f.class_name, f.field_name, f.type_name))
        .unwrap_or_else(|| format!("field@{}", idx))
}

fn safe_method(dex: &ParsedDex, idx: i64) -> String {
    dex.method_ids.get(idx as usize)
        .map(|m| format!("{}->{}{}", m.class_name, m.method_name, m.proto_desc))
        .unwrap_or_else(|| format!("method@{}", idx))
}

// ── Lookup tables ─────────────────────────────────────────────────────────────

const MODIFIER_TYPE_LOOKUP: [&str; 7] = ["", "-wide", "-object", "-boolean", "-byte", "-char", "-short"];
const INVOKE_TYPE_LOOKUP: [&str; 5]   = ["-virtual", "-super", "-direct", "-static", "-interface"];
const BIN_OPERATOR_LOOKUP: [&str; 11] = ["add", "sub", "mul", "div", "rem", "and", "or", "xor", "shl", "shr", "ushr"];
const BIN_OPERAND_LOOKUP: [&str; 4]   = ["int", "long", "float", "double"];

// ── Main decode entry point ───────────────────────────────────────────────────

/// Decode a single instruction from `insns_buf` at byte position `byte_pos`.
/// `dex` is used for string/type/field/method lookups.
/// Returns the decoded `Instruction`.
pub fn decode_instruction(
    insns_buf: &[u8],
    byte_pos: usize,
    codepoint: u32,
    dex: &ParsedDex,
) -> Option<Instruction> {
    let opcode = *insns_buf.get(byte_pos)?;
    let width = get_opcode_width(opcode)?;
    // Payload pseudo-instructions (opcode 0x00 with ident 0x01/0x02/0x03 —
    // packed-switch / sparse-switch / fill-array-data) have a *variable* width
    // that depends on their contents. Their static `get_opcode_width` is 1, so
    // slicing to `width*2` here would hand `decode_nop` a single byte and its
    // `payload.len() >= 7` guards would all fail — leaving the table undecoded
    // and the stream desynchronised. Give `decode_nop` the whole remaining
    // buffer; it computes and writes the real `instr.width`.
    let payload = if opcode == 0x00 {
        insns_buf.get(byte_pos + 1..)?
    } else {
        insns_buf.get(byte_pos + 1..byte_pos + width as usize * 2)?
    };

    let mut instr = Instruction::new(opcode, width);
    instr.address = byte_pos as u64;
    instr.codepoint = codepoint;

    dispatch_decode(&mut instr, opcode, payload, dex);
    instr.build_operands();
    Some(instr)
}

fn dispatch_decode(instr: &mut Instruction, opcode: u8, payload: &[u8], dex: &ParsedDex) {
    match opcode {
        0x00 => decode_nop(instr, payload, dex),
        0x01..=0x09 => decode_move(instr, payload),
        0x0a..=0x0d => decode_move_result(instr, payload),
        0x0e..=0x11 => decode_return(instr, payload),
        0x12..=0x1c => decode_const(instr, payload, dex),
        0x1d..=0x1e => decode_monitor(instr, payload),
        0x1f => decode_check_cast(instr, payload, dex),
        0x20 => decode_instance_of(instr, payload, dex),
        0x21 => decode_arr_length(instr, payload),
        0x22 => decode_new_instance(instr, payload, dex),
        0x23..=0x26 => decode_array(instr, payload, dex),
        0x27 => decode_throw(instr, payload),
        0x28..=0x2a => decode_goto(instr, payload),
        0x2b..=0x2c => decode_switch(instr, payload, dex),
        0x2d..=0x31 => decode_cmp(instr, payload),
        0x32..=0x37 => decode_if(instr, payload),
        0x38..=0x3d => decode_ifz(instr, payload),
        0x44..=0x51 => decode_array_op(instr, payload),
        0x52..=0x58 => decode_iget(instr, payload, dex),
        0x59..=0x5f => decode_iput(instr, payload, dex),
        0x60..=0x66 => decode_sget(instr, payload, dex),
        0x67..=0x6d => decode_sput(instr, payload, dex),
        0x6e..=0x72 => decode_invoke_kind(instr, payload, dex),
        0x74..=0x78 => decode_invoke_kind_range(instr, payload, dex),
        0x7b..=0x8f => decode_unop(instr, payload),
        0x90..=0xaf => decode_binop(instr, payload),
        0xb0..=0xcf => decode_binop2addr(instr, payload),
        0xd0..=0xe2 => decode_binoplit(instr, payload),
        0xfa..=0xfb => decode_invoke_polymorphic(instr, payload, dex),
        0xfc..=0xfd => decode_invoke_custom(instr, payload, dex),
        _ => {
            instr.fmt = "10x";
            instr.instruction_str = format!("unknown-opcode {:#04x}", opcode);
            instr.kind = InstructionKind::Unknown;
        }
    }
}

// ── Individual opcode decoders ────────────────────────────────────────────────

fn decode_nop(instr: &mut Instruction, payload: &[u8], dex: &ParsedDex) {
    instr.fmt = "10x";
    instr.kind = InstructionKind::Nop;

    let next = payload.first().copied().unwrap_or(0);
    match next {
        0x01 => {
            // packed-switch-payload
            if payload.len() >= 7 {
                let size      = u16::from_le_bytes([payload[1], payload[2]]);
                let first_key = i32::from_le_bytes([payload[3], payload[4], payload[5], payload[6]]);
                let mut targets = Vec::with_capacity(size as usize);
                let base = 7usize;
                for i in 0..size as usize {
                    let off = base + i * 4;
                    if off + 4 <= payload.len() {
                        targets.push(i32::from_le_bytes([
                            payload[off], payload[off+1], payload[off+2], payload[off+3],
                        ]));
                    }
                }
                instr.kind = InstructionKind::PackedSwitchPayload { size, first_key, targets };
                instr.width = 4 + (size as u32 * 2);
                instr.instruction_str = format!("; packed-switch-payload size={}", size);
            }
        }
        0x02 => {
            // sparse-switch-payload
            if payload.len() >= 3 {
                let size = u16::from_le_bytes([payload[1], payload[2]]);
                let n = size as usize;
                let mut keys    = Vec::with_capacity(n);
                let mut targets = Vec::with_capacity(n);
                let base = 3usize;
                for i in 0..n {
                    let off = base + i * 4;
                    if off + 4 <= payload.len() {
                        keys.push(i32::from_le_bytes([
                            payload[off], payload[off+1], payload[off+2], payload[off+3],
                        ]));
                    }
                }
                let tbase = base + n * 4;
                for i in 0..n {
                    let off = tbase + i * 4;
                    if off + 4 <= payload.len() {
                        targets.push(i32::from_le_bytes([
                            payload[off], payload[off+1], payload[off+2], payload[off+3],
                        ]));
                    }
                }
                instr.width = 2 + (size as u32 * 4);
                instr.kind = InstructionKind::SparseSwitchPayload { size, keys, targets };
                instr.instruction_str = format!("; sparse-switch-payload size={}", size);
            }
        }
        0x03 => {
            // fill-array-data-payload
            if payload.len() >= 7 {
                let element_width = u16::from_le_bytes([payload[1], payload[2]]);
                let element_count = u32::from_le_bytes([payload[3], payload[4], payload[5], payload[6]]);
                let data_bytes = (element_width as usize) * (element_count as usize);
                let padded = (data_bytes + 1) & !1;
                let data = payload.get(7..7 + data_bytes).unwrap_or(&[]).to_vec();
                instr.width = 4 + (padded as u32 / 2);
                instr.kind = InstructionKind::FillArrayDataPayload { element_width, element_count, data };
                instr.instruction_str = format!(
                    "; fill-array-data-payload elements={} width={}", element_count, element_width
                );
            }
        }
        _ => {
            instr.instruction_str = "nop".to_string();
        }
    }
}

fn decode_move(instr: &mut Instruction, payload: &[u8]) {
    let obj_types = ["", "-wide", "-object"];
    let suffix_iter = ((instr.opcode / 3) % 3) as usize;
    let prefix = format!("move{}", obj_types[suffix_iter]);
    let (fmt, suffix) = match instr.opcode {
        0x01 | 0x04 | 0x07 => ("12x", ""),
        0x02 | 0x05 | 0x08 => ("22x", "/from16"),
        0x03 | 0x06 | 0x09 => ("32x", "/16"),
        _ => ("12x", ""),
    };
    instr.fmt = fmt;
    decode_args(instr, payload);
    instr.instruction_str = format!("{}{} v{}, v{}", prefix, suffix, instr.v_a.unwrap_or(0), instr.v_b.unwrap_or(0));
    instr.kind = InstructionKind::Move;
}

fn decode_move_result(instr: &mut Instruction, payload: &[u8]) {
    instr.fmt = "11x";
    let prefix = match instr.opcode {
        0x0a => "move-result",
        0x0b => "move-result-wide",
        0x0c => "move-result-object",
        0x0d => "move-exception",
        _    => "move-result",
    };
    decode_args(instr, payload);
    instr.instruction_str = format!("{} v{}", prefix, instr.v_a.unwrap_or(0));
    instr.kind = InstructionKind::MoveResult;
}

fn decode_return(instr: &mut Instruction, payload: &[u8]) {
    instr.fmt = "11x";
    instr.control_flow = ControlFlow::Terminate;
    let prefix = match instr.opcode {
        0x0e => "return-void",
        0x0f => "return",
        0x10 => "return-wide",
        0x11 => "return-object",
        _    => "return",
    };
    decode_args(instr, payload);
    if instr.opcode == 0x0e {
        instr.instruction_str = prefix.to_string();
    } else {
        instr.instruction_str = format!("{} v{}", prefix, instr.v_a.unwrap_or(0));
    }
    instr.kind = InstructionKind::Return;
}

fn decode_const(instr: &mut Instruction, payload: &[u8], dex: &ParsedDex) {
    let (fmt, prefix, suffix): (&'static str, &str, &str) = match instr.opcode {
        0x12 => ("11n",  "const",       "/4"),
        0x13 => ("21s",  "const",       "/16"),
        0x14 => ("31i",  "const",       ""),
        0x15 => ("21h",  "const",       "/high16"),
        0x16 => ("21s",  "const-wide",  "/16"),
        0x17 => ("31i",  "const-wide",  "/32"),
        0x18 => ("51l",  "const-wide",  ""),
        0x19 => ("21h",  "const-wide",  "/high16"),
        0x1a => ("21c",  "const-string",""),
        0x1b => ("31c",  "const-string","/jumbo"),
        0x1c => ("21c",  "const-class", ""),
        _    => ("10x",  "const",       ""),
    };
    instr.fmt = fmt;
    decode_args(instr, payload);

    instr.instruction_str = match instr.opcode {
        0x1a | 0x1b => {
            let s = safe_string(dex, instr.v_b.unwrap_or(0));
            format!("{}{} v{}, \"{}\"", prefix, suffix, instr.v_a.unwrap_or(0), s)
        }
        0x1c => {
            let t = safe_type(dex, instr.v_b.unwrap_or(0));
            format!("{}{} v{}, {}", prefix, suffix, instr.v_a.unwrap_or(0), t)
        }
        _ => format!("{}{} v{}, {:#x}", prefix, suffix, instr.v_a.unwrap_or(0), instr.v_b.unwrap_or(0)),
    };
    instr.kind = InstructionKind::Const;
}

fn decode_monitor(instr: &mut Instruction, payload: &[u8]) {
    instr.fmt = "11x";
    let prefix = if instr.opcode == 0x1d { "monitor-enter" } else { "monitor-exit" };
    decode_args(instr, payload);
    instr.instruction_str = format!("{} v{}", prefix, instr.v_a.unwrap_or(0));
    instr.kind = InstructionKind::Monitor;
}

fn decode_check_cast(instr: &mut Instruction, payload: &[u8], dex: &ParsedDex) {
    instr.fmt = "21c";
    decode_args(instr, payload);
    let t = safe_type(dex, instr.v_b.unwrap_or(0));
    instr.instruction_str = format!("check-cast v{}, {}", instr.v_a.unwrap_or(0), t);
    instr.kind = InstructionKind::CheckCast;
}

fn decode_instance_of(instr: &mut Instruction, payload: &[u8], dex: &ParsedDex) {
    instr.fmt = "22c";
    decode_args(instr, payload);
    let t = safe_type(dex, instr.v_c.unwrap_or(0));
    instr.instruction_str = format!("instance-of v{}, v{}, {}", instr.v_a.unwrap_or(0), instr.v_b.unwrap_or(0), t);
    instr.kind = InstructionKind::InstanceOf;
}

fn decode_arr_length(instr: &mut Instruction, payload: &[u8]) {
    instr.fmt = "12x";
    decode_args(instr, payload);
    instr.instruction_str = format!("array-length v{}, v{}", instr.v_a.unwrap_or(0), instr.v_b.unwrap_or(0));
    instr.kind = InstructionKind::ArrLength;
}

fn decode_new_instance(instr: &mut Instruction, payload: &[u8], dex: &ParsedDex) {
    instr.fmt = "21c";
    decode_args(instr, payload);
    let t = safe_type(dex, instr.v_b.unwrap_or(0));
    instr.instruction_str = format!("new-instance v{}, {}", instr.v_a.unwrap_or(0), t);
    instr.kind = InstructionKind::NewInstance;
}

fn decode_array(instr: &mut Instruction, payload: &[u8], dex: &ParsedDex) {
    let (fmt, prefix, suffix): (&'static str, &str, &str) = match instr.opcode {
        0x23 => ("22c", "new-array",        ""),
        0x24 => ("35c", "filled-new-array", ""),
        0x25 => ("3rc", "filled-new-array", "/range"),
        0x26 => ("31t", "fill-array-data",  ""),
        _    => ("10x", "array",            ""),
    };
    instr.fmt = fmt;
    decode_args(instr, payload);

    instr.instruction_str = match instr.opcode {
        0x23 => {
            let t = safe_type(dex, instr.v_c.unwrap_or(0));
            format!("{} v{}, v{}, {}", prefix, instr.v_a.unwrap_or(0), instr.v_b.unwrap_or(0), t)
        }
        0x24 => {
            let t = safe_type(dex, instr.v_b.unwrap_or(0));
            let regs = [instr.v_c, instr.v_d, instr.v_e, instr.v_f, instr.v_g];
            let count = instr.v_a.unwrap_or(0) as usize;
            let args: String = regs[..count.min(5)]
                .iter().filter_map(|&v| v).map(|v| format!("v{}", v)).collect::<Vec<_>>().join(", ");
            format!("{} {{{}}}, {}", prefix, args, t)
        }
        0x25 => {
            let t = safe_type(dex, instr.v_b.unwrap_or(0));
            let vc = instr.v_c.unwrap_or(0);
            let va = instr.v_a.unwrap_or(0);
            format!("{}{} {{v{} .. v{}}}, {}", prefix, suffix, vc, vc + va - 1, t)
        }
        0x26 => format!("{} v{}, :array_UNRESOLVED", prefix, instr.v_a.unwrap_or(0)),
        _ => format!("{}", prefix),
    };
    instr.kind = InstructionKind::Array;
}

fn decode_throw(instr: &mut Instruction, payload: &[u8]) {
    instr.fmt = "11x";
    instr.control_flow = ControlFlow::Terminate;
    decode_args(instr, payload);
    instr.instruction_str = format!("throw v{}", instr.v_a.unwrap_or(0));
    instr.kind = InstructionKind::Throw;
}

fn decode_goto(instr: &mut Instruction, payload: &[u8]) {
    instr.control_flow = ControlFlow::GoTo;
    let (fmt, suffix): (&'static str, &str) = match instr.opcode {
        0x28 => ("10t", ""),
        0x29 => ("20t", "/16"),
        0x2a => ("30t", "/32"),
        _    => ("10t", ""),
    };
    instr.fmt = fmt;
    decode_args(instr, payload);
    instr.instruction_str = format!("goto{} :goto_UNRESOLVED", suffix);
    instr.kind = InstructionKind::Goto;
}

fn decode_switch(instr: &mut Instruction, payload: &[u8], dex: &ParsedDex) {
    instr.fmt = "31t";
    decode_args(instr, payload);

    // The switch table is in the instruction's payload data buffer
    // (payload is relative to address+1, so vB gives offset from codepoint)
    // We can only resolve the table at a higher level when the full insns buffer is available.
    // For now, emit a placeholder and leave table empty.
    instr.instruction_str = format!("switch v{}", instr.v_a.unwrap_or(0));
    instr.kind = InstructionKind::Switch { table: SwitchTable { table: HashMap::new() } };
    instr.control_flow = ControlFlow::Branch;
}

/// Resolve the switch table for a Switch instruction given the full insns buffer.
/// `byte_addr` is the byte address (within insns_buf) of the switch instruction.
pub fn resolve_switch_table(instr: &mut Instruction, insns_buf: &[u8]) {
    let v_b = match instr.v_b { Some(v) => v, None => return };
    let payload_byte_offset = (instr.address as i64 + v_b * 2) as usize;

    if payload_byte_offset + 4 > insns_buf.len() { return; }

    // Skip ident word (2 bytes)
    let base = payload_byte_offset + 2;
    if base + 2 > insns_buf.len() { return; }

    let num_elements = u16::from_le_bytes([insns_buf[base], insns_buf[base+1]]) as usize;
    let mut table = HashMap::new();

    if instr.opcode == 0x2b {
        // packed-switch
        if base + 2 + 4 + num_elements * 4 > insns_buf.len() { return; }
        let first_key = i32::from_le_bytes([
            insns_buf[base+2], insns_buf[base+3], insns_buf[base+4], insns_buf[base+5],
        ]);
        for i in 0..num_elements {
            let off = base + 6 + i * 4;
            let target = i32::from_le_bytes([
                insns_buf[off], insns_buf[off+1], insns_buf[off+2], insns_buf[off+3],
            ]);
            table.insert(first_key + i as i32, target);
        }
    } else {
        // sparse-switch
        if base + 2 + num_elements * 8 > insns_buf.len() { return; }
        let keys_base = base + 2;
        let tgt_base  = keys_base + num_elements * 4;
        for i in 0..num_elements {
            let ko = keys_base + i * 4;
            let to = tgt_base  + i * 4;
            let key = i32::from_le_bytes([insns_buf[ko], insns_buf[ko+1], insns_buf[ko+2], insns_buf[ko+3]]);
            let tgt = i32::from_le_bytes([insns_buf[to], insns_buf[to+1], insns_buf[to+2], insns_buf[to+3]]);
            table.insert(key, tgt);
        }
    }

    instr.kind = InstructionKind::Switch { table: SwitchTable { table } };
}

fn decode_cmp(instr: &mut Instruction, payload: &[u8]) {
    instr.fmt = "23x";
    let prefix = match instr.opcode {
        0x2d => "cmpl-float",
        0x2e => "cmpg-float",
        0x2f => "cmpl-double",
        0x30 => "cmpg-double",
        0x31 => "cmp-long",
        _    => "cmp",
    };
    decode_args(instr, payload);
    instr.instruction_str = format!("{} v{}, v{}, v{}", prefix, instr.v_a.unwrap_or(0), instr.v_b.unwrap_or(0), instr.v_c.unwrap_or(0));
    instr.kind = InstructionKind::Cmp;
}

fn decode_if(instr: &mut Instruction, payload: &[u8]) {
    instr.fmt = "22t";
    instr.control_flow = ControlFlow::Branch;
    let suffix = match instr.opcode {
        0x32 => "-eq", 0x33 => "-ne", 0x34 => "-lt",
        0x35 => "-ge", 0x36 => "-gt", 0x37 => "-le",
        _    => "",
    };
    decode_args(instr, payload);
    instr.instruction_str = format!("if{} v{}, v{}, :cond_UNRESOLVED", suffix, instr.v_a.unwrap_or(0), instr.v_b.unwrap_or(0));
    instr.kind = InstructionKind::If;
}

fn decode_ifz(instr: &mut Instruction, payload: &[u8]) {
    instr.fmt = "21t";
    instr.control_flow = ControlFlow::Branch;
    let suffix = match instr.opcode {
        0x38 => "-eqz", 0x39 => "-nez", 0x3a => "-ltz",
        0x3b => "-gez", 0x3c => "-gtz", 0x3d => "-lez",
        _    => "z",
    };
    decode_args(instr, payload);
    instr.instruction_str = format!("if{} v{}, :cond_UNRESOLVED", suffix, instr.v_a.unwrap_or(0));
    instr.kind = InstructionKind::IfZ;
}

fn decode_array_op(instr: &mut Instruction, payload: &[u8]) {
    instr.fmt = "23x";
    let prefix = if (0x44..=0x4a).contains(&instr.opcode) {
        format!("aget{}", MODIFIER_TYPE_LOOKUP[(instr.opcode - 0x44) as usize])
    } else {
        format!("aput{}", MODIFIER_TYPE_LOOKUP[(instr.opcode - 0x4b) as usize])
    };
    decode_args(instr, payload);
    instr.instruction_str = format!("{} v{}, v{}, v{}", prefix, instr.v_a.unwrap_or(0), instr.v_b.unwrap_or(0), instr.v_c.unwrap_or(0));
    instr.kind = InstructionKind::ArrayOp;
}

fn decode_iget(instr: &mut Instruction, payload: &[u8], dex: &ParsedDex) {
    instr.fmt = "22c";
    let prefix = format!("iget{}", MODIFIER_TYPE_LOOKUP[(instr.opcode - 0x52) as usize]);
    decode_args(instr, payload);
    let f = safe_field(dex, instr.v_c.unwrap_or(0));
    instr.instruction_str = format!("{} v{}, v{}, {}", prefix, instr.v_a.unwrap_or(0), instr.v_b.unwrap_or(0), f);
    instr.kind = InstructionKind::IGet;
}

fn decode_iput(instr: &mut Instruction, payload: &[u8], dex: &ParsedDex) {
    instr.fmt = "22c";
    let prefix = format!("iput{}", MODIFIER_TYPE_LOOKUP[(instr.opcode - 0x59) as usize]);
    decode_args(instr, payload);
    let f = safe_field(dex, instr.v_c.unwrap_or(0));
    instr.instruction_str = format!("{} v{}, v{}, {}", prefix, instr.v_a.unwrap_or(0), instr.v_b.unwrap_or(0), f);
    instr.kind = InstructionKind::IPut;
}

fn decode_sget(instr: &mut Instruction, payload: &[u8], dex: &ParsedDex) {
    instr.fmt = "21c";
    let prefix = format!("sget{}", MODIFIER_TYPE_LOOKUP[(instr.opcode - 0x60) as usize]);
    decode_args(instr, payload);
    let f = safe_field(dex, instr.v_b.unwrap_or(0));
    instr.instruction_str = format!("{} v{}, {}", prefix, instr.v_a.unwrap_or(0), f);
    instr.kind = InstructionKind::SGet;
}

fn decode_sput(instr: &mut Instruction, payload: &[u8], dex: &ParsedDex) {
    instr.fmt = "21c";
    let prefix = format!("sput{}", MODIFIER_TYPE_LOOKUP[(instr.opcode - 0x67) as usize]);
    decode_args(instr, payload);
    let f = safe_field(dex, instr.v_b.unwrap_or(0));
    instr.instruction_str = format!("{} v{}, {}", prefix, instr.v_a.unwrap_or(0), f);
    instr.kind = InstructionKind::SPut;
}

fn decode_invoke_kind(instr: &mut Instruction, payload: &[u8], dex: &ParsedDex) {
    instr.fmt = "35c";
    let prefix = format!("invoke{}", INVOKE_TYPE_LOOKUP[(instr.opcode - 0x6e) as usize]);
    decode_args(instr, payload);
    let m = safe_method(dex, instr.v_b.unwrap_or(0));
    let regs = [instr.v_c, instr.v_d, instr.v_e, instr.v_f, instr.v_g];
    let count = instr.v_a.unwrap_or(0) as usize;
    let args: String = regs[..count.min(5)].iter().filter_map(|&v| v).map(|v| format!("v{}", v)).collect::<Vec<_>>().join(", ");
    instr.instruction_str = format!("{} {{{}}}, {}", prefix, args, m);
    instr.kind = InstructionKind::InvokeKind;
}

fn decode_invoke_kind_range(instr: &mut Instruction, payload: &[u8], dex: &ParsedDex) {
    instr.fmt = "3rc";
    let prefix = format!("invoke{}", INVOKE_TYPE_LOOKUP[(instr.opcode - 0x74) as usize]);
    decode_args(instr, payload);
    let m = safe_method(dex, instr.v_b.unwrap_or(0));
    let vc = instr.v_c.unwrap_or(0);
    let va = instr.v_a.unwrap_or(0);
    instr.instruction_str = format!("{} {{v{} .. v{}}}, {}", prefix, vc, vc + va - 1, m);
    instr.kind = InstructionKind::InvokeKindRange;
}

fn decode_unop(instr: &mut Instruction, payload: &[u8]) {
    instr.fmt = "12x";
    let prefix = match instr.opcode {
        0x7b => "neg-int",       0x7c => "not-int",
        0x7d => "neg-long",      0x7e => "not-long",
        0x7f => "neg-float",     0x80 => "neg-double",
        0x81 => "int-to-long",   0x82 => "int-to-float",
        0x83 => "int-to-double", 0x84 => "long-to-int",
        0x85 => "long-to-float", 0x86 => "long-to-double",
        0x87 => "float-to-int",  0x88 => "float-to-long",
        0x89 => "float-to-double", 0x8a => "double-to-int",
        0x8b => "double-to-long",  0x8c => "double-to-float",
        0x8d => "int-to-byte",   0x8e => "int-to-char",
        0x8f => "int-to-short",  _    => "unop",
    };
    decode_args(instr, payload);
    instr.instruction_str = format!("{} v{}, v{}", prefix, instr.v_a.unwrap_or(0), instr.v_b.unwrap_or(0));
    instr.kind = InstructionKind::UnOp;
}

fn decode_binop(instr: &mut Instruction, payload: &[u8]) {
    instr.fmt = "23x";
    let (operator_type, operand_type) = if (0x90..=0xa5).contains(&instr.opcode) {
        let delta = instr.opcode - 0x90;
        (delta % 11, delta / 11)
    } else {
        let delta = instr.opcode - 0xa6;
        (delta % 5, delta / 5 + 2)
    };
    let prefix = format!("{}-{}", BIN_OPERATOR_LOOKUP[operator_type as usize], BIN_OPERAND_LOOKUP[operand_type as usize]);
    decode_args(instr, payload);
    instr.instruction_str = format!("{} v{}, v{}, v{}", prefix, instr.v_a.unwrap_or(0), instr.v_b.unwrap_or(0), instr.v_c.unwrap_or(0));
    instr.kind = InstructionKind::BinOp { operator_type, operand_type };
}

fn decode_binop2addr(instr: &mut Instruction, payload: &[u8]) {
    instr.fmt = "12x";
    let (operator_type, operand_type) = if (0xb0..=0xc5).contains(&instr.opcode) {
        let delta = instr.opcode - 0xb0;
        (delta % 11, delta / 11)
    } else {
        let delta = instr.opcode - 0xc6;
        (delta % 5, delta / 5 + 2)
    };
    let prefix = format!("{}-{}/2addr", BIN_OPERATOR_LOOKUP[operator_type as usize], BIN_OPERAND_LOOKUP[operand_type as usize]);
    decode_args(instr, payload);
    instr.instruction_str = format!("{} v{}, v{}", prefix, instr.v_a.unwrap_or(0), instr.v_b.unwrap_or(0));
    instr.kind = InstructionKind::BinOp2Addr { operator_type, operand_type };
}

fn decode_binoplit(instr: &mut Instruction, payload: &[u8]) {
    let (fmt, operator_type, suffix): (&'static str, u8, &str) = if (0xd0..=0xd7).contains(&instr.opcode) {
        ("22s", instr.opcode - 0xd0, "/lit16")
    } else {
        ("22b", instr.opcode - 0xd8, "/lit8")
    };
    instr.fmt = fmt;
    let prefix = format!("{}-int", BIN_OPERATOR_LOOKUP[operator_type as usize]);
    decode_args(instr, payload);
    instr.instruction_str = format!("{}{} v{}, v{}, {:#x}", prefix, suffix, instr.v_a.unwrap_or(0), instr.v_b.unwrap_or(0), instr.v_c.unwrap_or(0));
    instr.kind = InstructionKind::BinOpLit { operator_type };
}

fn decode_invoke_polymorphic(instr: &mut Instruction, payload: &[u8], dex: &ParsedDex) {
    let (fmt, suffix): (&'static str, &str) = match instr.opcode {
        0xfa => ("35c", ""),
        0xfb => ("3rc", "/range"),
        _    => ("35c", ""),
    };
    instr.fmt = fmt;
    decode_args(instr, payload);
    let m = safe_method(dex, instr.v_b.unwrap_or(0));
    instr.instruction_str = format!("invoke-polymorphic{} {}, proto@{}", suffix, m, instr.v_h.unwrap_or(0));
    instr.kind = InstructionKind::InvokePolymorphic;
}

fn decode_invoke_custom(instr: &mut Instruction, payload: &[u8], dex: &ParsedDex) {
    let (fmt, suffix): (&'static str, &str) = match instr.opcode {
        0xfc => ("35c", ""),
        0xfd => ("3rc", "/range"),
        _    => ("35c", ""),
    };
    instr.fmt = fmt;
    decode_args(instr, payload);
    instr.instruction_str = format!("invoke-custom{} call_site@{}", suffix, instr.v_b.unwrap_or(0));
    instr.kind = InstructionKind::InvokeCustom;
}

// ── Instruction stream decoder ────────────────────────────────────────────────

/// Decode all instructions from a raw insns buffer (code_item.insns).
/// Resolves switch tables in a second pass.
pub fn decode_instructions(insns: &[u8], dex: &ParsedDex) -> Vec<Instruction> {
    let mut instructions = Vec::new();
    let mut byte_pos: usize = 0;
    let mut codepoint: u32 = 0;

    while byte_pos < insns.len() {
        if let Some(mut instr) = decode_instruction(insns, byte_pos, codepoint, dex) {
            let w = instr.width;
            instructions.push(instr);
            byte_pos += w as usize * 2;
            codepoint += w;
        } else {
            break;
        }
    }

    // Second pass: resolve switch tables
    for i in 0..instructions.len() {
        let opcode = instructions[i].opcode;
        if opcode == 0x2b || opcode == 0x2c {
            // We need to mutably borrow one element while reading the buffer
            let addr = instructions[i].address;
            let v_b = instructions[i].v_b;
            if let Some(vb) = v_b {
                let payload_byte = (addr as i64 + vb * 2) as usize;
                if payload_byte + 2 < insns.len() {
                    // skip ident (2 bytes)
                    let base = payload_byte + 2;
                    let num_elements = u16::from_le_bytes([insns[base], insns[base+1]]) as usize;
                    let mut table = HashMap::new();
                    if opcode == 0x2b {
                        // packed-switch
                        if base + 6 + num_elements * 4 <= insns.len() {
                            let first_key = i32::from_le_bytes([
                                insns[base+2], insns[base+3], insns[base+4], insns[base+5],
                            ]);
                            for j in 0..num_elements {
                                let off = base + 6 + j * 4;
                                let t = i32::from_le_bytes([insns[off], insns[off+1], insns[off+2], insns[off+3]]);
                                table.insert(first_key + j as i32, t);
                            }
                        }
                    } else {
                        // sparse-switch
                        let keys_base = base + 2;
                        let tgt_base  = keys_base + num_elements * 4;
                        if tgt_base + num_elements * 4 <= insns.len() {
                            for j in 0..num_elements {
                                let ko = keys_base + j * 4;
                                let to = tgt_base  + j * 4;
                                let k = i32::from_le_bytes([insns[ko], insns[ko+1], insns[ko+2], insns[ko+3]]);
                                let t = i32::from_le_bytes([insns[to], insns[to+1], insns[to+2], insns[to+3]]);
                                table.insert(k, t);
                            }
                        }
                    }
                    instructions[i].kind = InstructionKind::Switch { table: SwitchTable { table } };
                }
            }
        }
    }

    instructions
}

#[cfg(test)]
mod payload_tests {
    use super::*;
    use crate::parser::{DexHeader, ParsedDex};

    fn empty_dex() -> ParsedDex {
        ParsedDex {
            header: DexHeader {
                magic: [0; 4], version_str: String::new(), checksum: 0, signature: [0; 20],
                file_size: 0, header_size: 0, endian_tag: 0, link_size: 0, link_off: 0, map_off: 0,
                string_ids_size: 0, string_ids_off: 0, type_ids_size: 0, type_ids_off: 0,
                proto_ids_size: 0, proto_ids_off: 0, field_ids_size: 0, field_ids_off: 0,
                method_ids_size: 0, method_ids_off: 0, class_defs_size: 0, class_defs_off: 0,
                data_size: 0, data_off: 0,
            },
            strings: vec![], type_ids: vec![], proto_ids: vec![], field_ids: vec![],
            method_ids: vec![], class_defs: vec![], digest: String::new(), filename: String::new(),
        }
    }

    /// Regression: a `fill-array-data-payload` (opcode 0x00, ident 0x0300) has a
    /// variable width that depends on its contents. The decoder must hand
    /// `decode_nop` the full remaining buffer (not a 1-byte slice sized to the
    /// nop's static width) so the table decodes and the stream stays in sync.
    #[test]
    fn fill_array_data_payload_decodes_and_keeps_sync() {
        // payload: ident=0x0300, element_width=1, count=3, data=[41,42,43]+pad
        // then a return-void (0x0e 0x00).
        let insns: Vec<u8> = vec![
            0x00, 0x03, // ident 0x0300
            0x01, 0x00, // element_width = 1
            0x03, 0x00, 0x00, 0x00, // element_count = 3
            0x41, 0x42, 0x43, 0x00, // 3 data bytes + 1 pad
            0x0e, 0x00, // return-void
        ];
        let dex = empty_dex();
        let out = decode_instructions(&insns, &dex);

        assert_eq!(out.len(), 2, "payload (6 units) + return-void, in sync");
        match &out[0].kind {
            InstructionKind::FillArrayDataPayload { element_width, element_count, data } => {
                assert_eq!(*element_width, 1);
                assert_eq!(*element_count, 3);
                assert_eq!(data, &[0x41, 0x42, 0x43]);
            }
            other => panic!("expected FillArrayDataPayload, got {:?}", other),
        }
        assert_eq!(out[0].width, 6, "width = 4 + ceil(3/2)");
        assert_eq!(out[1].opcode, 0x0e, "return-void must decode right after the payload");
        assert_eq!(out[1].codepoint, 6, "codepoint stayed in sync");
    }
}
