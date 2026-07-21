/// Call-site resolver — translates vm/call_site_resolver.py
///
/// Resolves invoke-dynamic call sites via bootstrap method handles.
/// This is a structural translation; full execution requires a live VM.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MethodHandleType {
    StaticPut         = 0x00,
    StaticGet         = 0x01,
    InstancePut       = 0x02,
    InstanceGet       = 0x03,
    InvokeStatic      = 0x04,
    InvokeInstance    = 0x05,
    InvokeDirect      = 0x06,
    InvokeInterface   = 0x07,
    InvokeConstructor = 0x08,
}

impl MethodHandleType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x00 => Some(Self::StaticPut),
            0x01 => Some(Self::StaticGet),
            0x02 => Some(Self::InstancePut),
            0x03 => Some(Self::InstanceGet),
            0x04 => Some(Self::InvokeStatic),
            0x05 => Some(Self::InvokeInstance),
            0x06 => Some(Self::InvokeDirect),
            0x07 => Some(Self::InvokeInterface),
            0x08 => Some(Self::InvokeConstructor),
            _ => None,
        }
    }
}

/// A resolved method/field handle.
#[derive(Debug, Clone)]
pub struct ResolvedHandle {
    pub kind: MethodHandleType,
    /// Index into method_ids or field_ids (depending on kind).
    pub idx:  usize,
}

/// Stub resolver — real resolution requires a running VM with the parsed DEX.
pub struct CallSiteResolver;

impl CallSiteResolver {
    pub fn new() -> Self { CallSiteResolver }
}

impl Default for CallSiteResolver {
    fn default() -> Self { Self::new() }
}
