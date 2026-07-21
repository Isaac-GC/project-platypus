/// Method representation — translates dex/method.py

use std::io;

use super::access_flags::{MethodAccessFlag, parse_method_access_flags};
use super::code_block::{Cfg, CfgBuilder};
use super::instructions::{Instruction, decode_instructions};
use super::parser::{DexFileWithRaw, EncodedMethod, TryItem, EncodedCatchHandler};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MethodType {
    Virtual,
    Direct,
}

#[derive(Debug, Clone)]
pub struct Method {
    pub method_idx: usize,
    pub method_type: MethodType,
    pub class_name: String,
    pub method_name: String,
    pub signature: String,
    pub proto_desc: String,
    pub access_flags: Vec<MethodAccessFlag>,
    pub code_offset: u64,

    // Only populated when code_offset != 0
    pub registers_size: u16,
    pub ins_size: u16,
    pub outs_size: u16,
    pub instructions: Vec<Instruction>,
    pub try_items: Vec<TryItem>,
    pub handlers: Vec<EncodedCatchHandler>,
    pub cfg: Option<Cfg>,
    /// Codepoint → source line table (empty if no debug info).
    pub line_map: Vec<(u32, u32)>,
    /// Annotations attached to this method (declaration-level).
    /// Populated by Clazz::new from the owning ClassDefItem's
    /// `method_annotations` map. Empty when the method has none.
    pub annotations: Vec<crate::parser::AnnotationItem>,
    /// Per-parameter annotations, indexed by parameter position
    /// (0-based; corresponds to user-facing param indices, not
    /// register indices). Empty when no parameter is annotated;
    /// non-empty outer Vec with empty inner Vecs is possible when
    /// only some parameters are annotated.
    pub param_annotations: Vec<Vec<crate::parser::AnnotationItem>>,
}

impl Method {
    /// Parse a method from an `EncodedMethod`, resolving metadata and instructions.
    pub fn new(
        curr_idx: usize,
        encoded: &EncodedMethod,
        method_type: MethodType,
        dex: &DexFileWithRaw,
    ) -> io::Result<Self> {
        let method_id = dex.parsed.method_ids.get(curr_idx).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, format!("method_id {} out of range", curr_idx))
        })?;

        let class_name  = method_id.class_name.clone();
        let method_name = method_id.method_name.clone();
        let signature   = format!("{}-> {}", class_name, method_name);
        let proto_desc  = method_id.proto_desc.clone();
        let access_flags = parse_method_access_flags(encoded.access_flags as u32);
        let code_offset = encoded.code_off;

        let mut method = Method {
            method_idx: curr_idx,
            method_type,
            class_name,
            method_name,
            signature,
            proto_desc,
            access_flags,
            code_offset,
            registers_size: 0,
            ins_size: 0,
            outs_size: 0,
            instructions: Vec::new(),
            try_items: Vec::new(),
            handlers: Vec::new(),
            cfg: None,
            line_map: Vec::new(),
            // Annotations get layered on by Clazz::new from the
            // class_def's per-method map after construction. The
            // method_idx (curr_idx above) is the lookup key.
            annotations: Vec::new(),
            param_annotations: Vec::new(),
        };

        if code_offset != 0 {
            let code_item = dex.read_code_item(code_offset)?;
            method.registers_size = code_item.registers_size;
            method.ins_size       = code_item.ins_size;
            method.outs_size      = code_item.outs_size;
            method.try_items      = code_item.try_items.clone();
            method.handlers       = code_item.handlers.clone();

            method.instructions = decode_instructions(&code_item.insns, &dex.parsed);

            // Build CFG
            let builder = CfgBuilder::new(&method.instructions);
            method.cfg = Some(builder.build(&code_item.try_items, &code_item.handlers));

            // Parse debug info to build codepoint → line table
            if code_item.debug_info_off != 0 {
                method.line_map = crate::debug_info::parse_line_table(
                    dex.raw_bytes(),
                    code_item.debug_info_off as usize,
                );
            }
        }

        Ok(method)
    }

    pub fn is_native(&self) -> bool {
        self.access_flags.contains(&MethodAccessFlag::Native)
    }

    pub fn is_abstract(&self) -> bool {
        self.access_flags.contains(&MethodAccessFlag::Abstract)
    }

    pub fn is_static(&self) -> bool {
        self.access_flags.contains(&MethodAccessFlag::Static)
    }
}
