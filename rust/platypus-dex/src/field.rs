/// Field representation — translates dex/field.py

use super::access_flags::{FieldAccessFlag, parse_field_access_flags};
use super::parser::{DexFileWithRaw, FieldIdItem};

#[derive(Debug, Clone)]
pub struct Field {
    pub field_idx: usize,
    pub access_flags: Vec<FieldAccessFlag>,
    pub class_name: String,
    pub type_name: String,
    pub name: String,
    /// Annotations attached to this field. Populated by Clazz::new
    /// from the owning ClassDefItem's `field_annotations` map.
    pub annotations: Vec<crate::parser::AnnotationItem>,
}

impl Field {
    pub fn new(curr_idx: usize, raw_access_flags: u64, dex: &DexFileWithRaw) -> Option<Self> {
        let field_id: &FieldIdItem = dex.parsed.field_ids.get(curr_idx)?;
        let access_flags = parse_field_access_flags(raw_access_flags as u32);

        Some(Field {
            field_idx: curr_idx,
            access_flags,
            class_name: field_id.class_name.clone(),
            type_name:  field_id.type_name.clone(),
            name:       field_id.field_name.clone(),
            // Annotations get layered on by Clazz::new — see the field
            // doc for the lookup model.
            annotations: Vec::new(),
        })
    }
}
