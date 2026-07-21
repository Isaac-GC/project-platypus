/// Smali code generator — translates codegen/smali/smali_generator.py

use std::collections::HashMap;

use platypus_dex::access_flags::MethodAccessFlag;
use platypus_dex::clazz::Clazz;
use platypus_dex::helpers::sign_extend;
use platypus_dex::instructions::{Instruction, InstructionKind};
use platypus_dex::method::Method;
use platypus_dex::parser::ParsedDex;

// ── SmaliCodeGen ─────────────────────────────────────────────────────────────

pub struct SmaliCodeGen<'a> {
    method:     &'a Method,
    dex:        &'a ParsedDex,
    label_map:  HashMap<u32, Vec<String>>, // codepoint → labels
}

impl<'a> SmaliCodeGen<'a> {
    pub fn new(method: &'a Method, dex: &'a ParsedDex) -> Self {
        let mut gen = SmaliCodeGen { method, dex, label_map: HashMap::new() };
        gen.build_labels();
        gen
    }

    fn add_label(&mut self, codepoint: u32, label: String) {
        let entry = self.label_map.entry(codepoint).or_default();
        if !entry.contains(&label) {
            entry.push(label);
        }
    }

    fn build_labels(&mut self) {
        for instr in &self.method.instructions {
            let op = instr.opcode;

            // goto family
            if (0x28..=0x2a).contains(&op) {
                let bits = match op { 0x28 => 8, 0x29 => 16, _ => 32 };
                let target = (instr.codepoint as i64 + sign_extend(instr.v_a.unwrap_or(0), bits)) as u32;
                self.add_label(target, format!(":goto_{:x}", target));
            }
            // if-* two-register
            else if (0x32..=0x37).contains(&op) {
                let target = (instr.codepoint as i64 + sign_extend(instr.v_c.unwrap_or(0), 16)) as u32;
                self.add_label(target, format!(":cond_{:x}", target));
            }
            // if-*z
            else if (0x38..=0x3d).contains(&op) {
                let target = (instr.codepoint as i64 + sign_extend(instr.v_b.unwrap_or(0), 16)) as u32;
                self.add_label(target, format!(":cond_{:x}", target));
            }
            // switch
            else if op == 0x2b || op == 0x2c {
                let kind = if op == 0x2b { "pswitch" } else { "sswitch" };
                if let InstructionKind::Switch { ref table } = instr.kind {
                    for &rel in table.table.values() {
                        let target = (instr.codepoint as i64 + rel as i64) as u32;
                        self.add_label(target, format!(":{kind}_{:x}", target));
                    }
                }
            }
            // fill-array-data
            else if op == 0x26 {
                let target = (instr.codepoint as i64 + sign_extend(instr.v_b.unwrap_or(0), 32)) as u32;
                self.add_label(target, format!(":array_{:x}", target));
            }
        }

        // try/catch labels
        for try_item in &self.method.try_items {
            let start = try_item.start_addr;
            let end   = start + try_item.insn_count as u32;
            self.add_label(start, format!(":try_start_{:x}", start));
            self.add_label(end,   format!(":try_end_{:x}", start));
        }
    }

    fn format_register(&self, reg: i64) -> String {
        let param_start = self.method.registers_size as i64 - self.method.ins_size as i64;
        if reg >= param_start {
            format!("p{}", reg - param_start)
        } else {
            format!("v{}", reg)
        }
    }

    fn fr(&self, reg: Option<i64>) -> String {
        reg.map(|r| self.format_register(r)).unwrap_or_default()
    }

    fn format_instruction(&self, instr: &Instruction) -> String {
        let op = instr.opcode;

        if op == 0x28 {
            let t = (instr.codepoint as i64 + sign_extend(instr.v_a.unwrap_or(0), 8)) as u32;
            return format!("goto :goto_{:x}", t);
        }
        if op == 0x29 {
            let t = (instr.codepoint as i64 + sign_extend(instr.v_a.unwrap_or(0), 16)) as u32;
            return format!("goto/16 :goto_{:x}", t);
        }
        if op == 0x2a {
            let t = (instr.codepoint as i64 + sign_extend(instr.v_a.unwrap_or(0), 32)) as u32;
            return format!("goto/32 :goto_{:x}", t);
        }

        if (0x32..=0x37).contains(&op) {
            let t = (instr.codepoint as i64 + sign_extend(instr.v_c.unwrap_or(0), 16)) as u32;
            let mnem = instr.instruction_str.split_whitespace().next().unwrap_or("if");
            return format!("{} {}, {}, :cond_{:x}", mnem, self.fr(instr.v_a), self.fr(instr.v_b), t);
        }
        if (0x38..=0x3d).contains(&op) {
            let t = (instr.codepoint as i64 + sign_extend(instr.v_b.unwrap_or(0), 16)) as u32;
            let mnem = instr.instruction_str.split_whitespace().next().unwrap_or("if");
            return format!("{} {}, :cond_{:x}", mnem, self.fr(instr.v_a), t);
        }

        if op == 0x2b || op == 0x2c {
            let (kind_full, kind_short) = if op == 0x2b {
                ("packed-switch", "p")
            } else {
                ("sparse-switch", "s")
            };
            let t = (instr.codepoint as i64 + instr.v_b.unwrap_or(0)) as u32;
            return format!("{} {}, :{}switch_{:x}", kind_full, self.fr(instr.v_a), kind_short, t);
        }

        if op == 0x26 {
            let t = (instr.codepoint as i64 + sign_extend(instr.v_b.unwrap_or(0), 32)) as u32;
            return format!("fill-array-data {}, :array_{:x}", self.fr(instr.v_a), t);
        }

        // invoke-*  (0x6e..=0x72)
        if (0x6e..=0x72).contains(&op) {
            let arg_count = instr.v_a.unwrap_or(0) as usize;
            let regs: Vec<String> = [instr.v_c, instr.v_d, instr.v_e, instr.v_f, instr.v_g]
                .iter()
                .take(arg_count)
                .filter_map(|&r| r)
                .map(|r| self.fr(Some(r)))
                .collect();
            let args = regs.join(", ");
            let method_ref = instr.v_b.and_then(|idx| self.dex.method_ids.get(idx as usize));
            let ref_str = method_ref.map(|m| format!("{}->{}{}", m.class_name, m.method_name, m.proto_desc))
                .unwrap_or_else(|| "<unknown>".to_string());
            let mnem = instr.instruction_str.split_whitespace().next().unwrap_or("invoke");
            return format!("{} {{{}}}, {}", mnem, args, ref_str);
        }

        // invoke-*/range (0x74..=0x78)
        if (0x74..=0x78).contains(&op) {
            let start_reg = instr.v_c.unwrap_or(0);
            let count = instr.v_a.unwrap_or(0);
            let end_reg = start_reg + count - 1;
            let method_ref = instr.v_b.and_then(|idx| self.dex.method_ids.get(idx as usize));
            let ref_str = method_ref.map(|m| format!("{}->{}{}", m.class_name, m.method_name, m.proto_desc))
                .unwrap_or_else(|| "<unknown>".to_string());
            let mnem = instr.instruction_str.split_whitespace().next().unwrap_or("invoke");
            return format!("{} {{v{} .. v{}}}, {}", mnem, self.fr(Some(start_reg)), self.fr(Some(end_reg)), ref_str);
        }

        // iget/iput (0x52..=0x5f)
        if (0x52..=0x5f).contains(&op) {
            let field_ref = instr.v_c.and_then(|idx| self.dex.field_ids.get(idx as usize));
            let ref_str = field_ref.map(|f| format!("{}->{}.{}", f.class_name, f.field_name, f.type_name))
                .unwrap_or_else(|| "<unknown>".to_string());
            let mnem = instr.instruction_str.split_whitespace().next().unwrap_or("iget");
            return format!("{} {}, {}, {}", mnem, self.fr(instr.v_a), self.fr(instr.v_b), ref_str);
        }

        // sget/sput (0x60..=0x6d)
        if (0x60..=0x6d).contains(&op) {
            let field_ref = instr.v_b.and_then(|idx| self.dex.field_ids.get(idx as usize));
            let ref_str = field_ref.map(|f| format!("{}->{}.{}", f.class_name, f.field_name, f.type_name))
                .unwrap_or_else(|| "<unknown>".to_string());
            let mnem = instr.instruction_str.split_whitespace().next().unwrap_or("sget");
            return format!("{} {}, {}", mnem, self.fr(instr.v_a), ref_str);
        }

        instr.instruction_str.clone()
    }

    fn format_switch_tables(&self) -> Vec<String> {
        let mut lines = Vec::new();
        for instr in &self.method.instructions {
            if instr.opcode != 0x2b && instr.opcode != 0x2c {
                continue;
            }
            let kind = if instr.opcode == 0x2b { "pswitch" } else { "sswitch" };
            let target = (instr.codepoint as i64 + sign_extend(instr.v_b.unwrap_or(0), 32)) as u32;
            lines.push(String::new());
            lines.push(format!("\t:{kind}-data_{:x}", target));
            if let InstructionKind::Switch { ref table } = instr.kind {
                for (&key, &rel) in &table.table {
                    let abs_target = (instr.codepoint as i64 + rel as i64) as u32;
                    lines.push(format!("\t\t{:#x}_{:x}", key, abs_target));
                }
            }
            lines.push(format!("\t:{kind}-data-end_{:x}", target));
        }
        lines
    }

    fn format_array_payloads(&self) -> Vec<String> {
        let mut lines = Vec::new();
        for instr in &self.method.instructions {
            if instr.opcode != 0x26 {
                continue;
            }
            let target = (instr.codepoint as i64 + sign_extend(instr.v_b.unwrap_or(0), 32)) as u32;
            lines.push(String::new());
            lines.push(format!("    :array_{:x}", target));
            if let InstructionKind::FillArrayDataPayload { element_width, ref data, .. } = instr.kind {
                lines.push(format!("    .array-data {}", element_width));
                for byte in data {
                    lines.push(format!("        {:#x}", byte));
                }
            }
            lines.push("    .end array-data".to_string());
        }
        lines
    }

    fn format_catch_statements(&self) -> Vec<String> {
        let mut lines = Vec::new();
        for try_item in &self.method.try_items {
            let start = try_item.start_addr;
            let end   = start + try_item.insn_count as u32;
            for handler in &self.method.handlers {
                for h in &handler.handlers {
                    let type_name = self.dex.type_ids
                        .get(h.type_idx as usize)
                        .map(|t| t.type_name.as_str())
                        .unwrap_or("<type?>");
                    lines.push(format!(
                        "\t.catch {} {{:try_start_{:x} .. :try_end_{:x}}}:catch_{:x}",
                        type_name, start, start, h.addr
                    ));
                }
                if let Some(catch_all) = handler.catch_all_addr {
                    lines.push(format!(
                        "\t.catchall {{:try_start_{:x} .. :try_end_{:x}}}:catch_all_{:x}",
                        start, start, catch_all
                    ));
                }
            }
            let _ = end; // suppress warning; end used implicitly via labels
        }
        lines
    }

    pub fn format_all(&self) -> String {
        let m = self.method;
        let mut lines: Vec<String> = Vec::new();

        let access_str = format_method_flags(&m.access_flags);
        lines.push(format!(".method {} {}{}", access_str, m.method_name, m.proto_desc));
        lines.push(format!("\t.registers {}", m.registers_size));
        lines.push(String::new());

        for instr in &m.instructions {
            if let Some(labels) = self.label_map.get(&instr.codepoint) {
                for label in labels {
                    lines.push(format!("\t{}", label));
                }
            }
            lines.push(format!("\t{}", self.format_instruction(instr)));
        }

        lines.extend(self.format_catch_statements());
        lines.extend(self.format_switch_tables());
        lines.extend(self.format_array_payloads());
        lines.push(".end method".to_string());

        lines.join("\n")
    }
}

// ── SmaliClassCodeGen ────────────────────────────────────────────────────────

pub struct SmaliClassCodeGen<'a> {
    clazz: &'a Clazz,
    dex:   &'a ParsedDex,
}

impl<'a> SmaliClassCodeGen<'a> {
    pub fn new(clazz: &'a Clazz, dex: &'a ParsedDex) -> Self {
        SmaliClassCodeGen { clazz, dex }
    }

    pub fn format(&self) -> String {
        let c = self.clazz;
        let mut lines: Vec<String> = Vec::new();

        let access = format_class_flags(&c.access_flags);
        lines.push(format!(".class {} {}", access, c.class_name));

        // Superclass and source: not currently stored in Clazz; emit defaults
        lines.push(".super Ljava/lang/Object;".to_string());

        // Static fields
        if !c.static_fields.is_empty() {
            lines.push(String::new());
            lines.push("# static fields".to_string());
            for field in &c.static_fields {
                let af = format_field_flags(&field.access_flags);
                lines.push(format!(".field {} {}:{}", af, field.name, field.type_name));
            }
        }

        // Instance fields
        if !c.instance_fields.is_empty() {
            lines.push(String::new());
            lines.push("# instance fields".to_string());
            for field in &c.instance_fields {
                let af = format_field_flags(&field.access_flags);
                lines.push(format!(".field {} {}:{}", af, field.name, field.type_name));
            }
        }

        // Methods
        for method in &c.methods {
            lines.push(String::new());
            if method.code_offset == 0 {
                let af = format_method_flags(&method.access_flags);
                lines.push(format!(
                    ".method {} {}{}\n.end method",
                    af, method.method_name, method.proto_desc
                ));
            } else {
                let gen = SmaliCodeGen::new(method, self.dex);
                lines.push(gen.format_all());
            }
        }

        lines.join("\n")
    }
}

// ── Flag formatters ───────────────────────────────────────────────────────────

fn format_method_flags(flags: &[MethodAccessFlag]) -> String {
    flags.iter()
        .map(|f| format!("{:?}", f).to_lowercase())
        .collect::<Vec<_>>()
        .join(" ")
}

fn format_class_flags(flags: &[platypus_dex::access_flags::ClassAccessFlag]) -> String {
    flags.iter()
        .map(|f| format!("{:?}", f).to_lowercase())
        .collect::<Vec<_>>()
        .join(" ")
}

fn format_field_flags(flags: &[platypus_dex::access_flags::FieldAccessFlag]) -> String {
    flags.iter()
        .map(|f| format!("{:?}", f).to_lowercase())
        .collect::<Vec<_>>()
        .join(" ")
}
