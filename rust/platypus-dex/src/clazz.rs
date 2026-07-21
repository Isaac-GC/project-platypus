/// Class representation — translates dex/clazz.py

use std::io;

use super::access_flags::{ClassAccessFlag, parse_class_access_flags};
use super::field::Field;
use super::method::{Method, MethodType};
use super::parser::{AnnotationItem, ClassDefItem, DexFileWithRaw};

#[derive(Debug)]
pub struct Clazz {
    pub class_id: u32,
    pub class_name: String,
    pub access_flags: Vec<ClassAccessFlag>,
    pub methods: Vec<Method>,
    pub static_fields: Vec<Field>,
    pub instance_fields: Vec<Field>,
    /// Superclass descriptor (e.g. `"Ljava/lang/Object;"`). Empty for
    /// `java/lang/Object` itself (the only class with no superclass).
    pub superclass_name: String,
    /// Implemented interface descriptors, declaration order.
    pub interfaces: Vec<String>,
    /// Class-level annotations with element values. See
    /// `ClassDefItem.annotations` for the parsing scope.
    pub annotations: Vec<AnnotationItem>,
}

impl Clazz {
    pub fn new(class_def: &ClassDefItem, dex: &DexFileWithRaw) -> io::Result<Self> {
        let class_id    = class_def.class_idx;
        let class_name  = class_def.type_name.clone();
        let access_flags = parse_class_access_flags(class_def.access_flags);
        let superclass_name = class_def.superclass_name.clone();
        let interfaces = class_def.interfaces.clone();
        let annotations = class_def.annotations.clone();

        let mut methods: Vec<Method>         = Vec::new();
        let mut static_fields: Vec<Field>    = Vec::new();
        let mut instance_fields: Vec<Field>  = Vec::new();

        if let Some(ref class_data) = class_def.class_data {
            // --- virtual methods ---
            let mut curr_idx: usize = 0;
            for e in &class_data.virtual_methods {
                curr_idx = if curr_idx == 0 {
                    e.method_idx_diff as usize
                } else {
                    curr_idx + e.method_idx_diff as usize
                };
                match Method::new(curr_idx, e, MethodType::Virtual, dex) {
                    Ok(m) => methods.push(m),
                    Err(err) => eprintln!("[-] Warning: failed to parse virtual method {}: {}", curr_idx, err),
                }
            }

            // --- direct methods ---
            curr_idx = 0;
            for e in &class_data.direct_methods {
                curr_idx = if curr_idx == 0 {
                    e.method_idx_diff as usize
                } else {
                    curr_idx + e.method_idx_diff as usize
                };
                match Method::new(curr_idx, e, MethodType::Direct, dex) {
                    Ok(m) => methods.push(m),
                    Err(err) => eprintln!("[-] Warning: failed to parse direct method {}: {}", curr_idx, err),
                }
            }

            // --- static fields ---
            curr_idx = 0;
            for e in &class_data.static_fields {
                curr_idx = if curr_idx == 0 {
                    e.field_idx_diff as usize
                } else {
                    curr_idx + e.field_idx_diff as usize
                };
                if let Some(f) = Field::new(curr_idx, e.access_flags, dex) {
                    static_fields.push(f);
                }
            }

            // --- instance fields ---
            curr_idx = 0;
            for e in &class_data.instance_fields {
                curr_idx = if curr_idx == 0 {
                    e.field_idx_diff as usize
                } else {
                    curr_idx + e.field_idx_diff as usize
                };
                if let Some(f) = Field::new(curr_idx, e.access_flags, dex) {
                    instance_fields.push(f);
                }
            }
        }

        // ── Layer per-method / per-field annotations onto the
        //    just-constructed Method/Field instances ───────────────
        //
        // The dex stores these in a sparse map (method_idx → [annotations],
        // field_idx → [annotations]) that ONLY mentions members which
        // actually have annotations — so most lookups return None and
        // the corresponding member's `annotations` stays empty.
        for m in &mut methods {
            let key = m.method_idx as u32;
            if let Some(anns) = class_def.method_annotations.get(&key) {
                m.annotations = anns.clone();
            }
            if let Some(params) = class_def.parameter_annotations.get(&key) {
                m.param_annotations = params.clone();
            }
        }
        for f in static_fields.iter_mut().chain(instance_fields.iter_mut()) {
            if let Some(anns) = class_def.field_annotations.get(&(f.field_idx as u32)) {
                f.annotations = anns.clone();
            }
        }

        Ok(Clazz {
            class_id,
            class_name,
            access_flags,
            methods,
            static_fields,
            instance_fields,
            superclass_name,
            interfaces,
            annotations,
        })
    }
}
