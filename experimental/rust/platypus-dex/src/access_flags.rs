/// Access flag enums — translates dex/access_flags.py

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MethodAccessFlag {
    Public             = 0x0001,
    Private            = 0x0002,
    Protected          = 0x0004,
    Static             = 0x0008,
    Final              = 0x0010,
    Synchronized       = 0x0020,
    Bridge             = 0x0040,
    Varargs            = 0x0080,
    Native             = 0x0100,
    Abstract           = 0x0400,
    Strict             = 0x0800,
    Synthetic          = 0x1000,
    Constructor        = 0x10000,
    DeclaredSynchronized = 0x20000,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ClassAccessFlag {
    Public       = 0x0001,
    Private      = 0x0002,
    Protected    = 0x0004,
    Static       = 0x0008,
    Final        = 0x0010,
    Super        = 0x0020,
    Interface    = 0x0200,
    Abstract     = 0x0400,
    Synthetic    = 0x1000,
    Annotation   = 0x2000,
    Enum         = 0x4000,
    Constructor  = 0x10000,
    ClassIsProxy = 0x40000,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FieldAccessFlag {
    Public              = 0x0001,
    Private             = 0x0002,
    Protected           = 0x0004,
    Static              = 0x0008,
    Final               = 0x0010,
    Volatile            = 0x0040,
    Synthetic           = 0x1000,
    Enum                = 0x4000,
    Constructor         = 0x10000,
    DeclaredSynchronized = 0x20000,
}

/// Parse a raw u32 bitfield into a list of MethodAccessFlag values.
pub fn parse_method_access_flags(raw: u32) -> Vec<MethodAccessFlag> {
    let all = [
        MethodAccessFlag::Public,
        MethodAccessFlag::Private,
        MethodAccessFlag::Protected,
        MethodAccessFlag::Static,
        MethodAccessFlag::Final,
        MethodAccessFlag::Synchronized,
        MethodAccessFlag::Bridge,
        MethodAccessFlag::Varargs,
        MethodAccessFlag::Native,
        MethodAccessFlag::Abstract,
        MethodAccessFlag::Strict,
        MethodAccessFlag::Synthetic,
        MethodAccessFlag::Constructor,
        MethodAccessFlag::DeclaredSynchronized,
    ];
    all.iter().filter(|&&f| raw & (f as u32) != 0).copied().collect()
}

/// Parse a raw u32 bitfield into a list of ClassAccessFlag values.
pub fn parse_class_access_flags(raw: u32) -> Vec<ClassAccessFlag> {
    let all = [
        ClassAccessFlag::Public,
        ClassAccessFlag::Private,
        ClassAccessFlag::Protected,
        ClassAccessFlag::Static,
        ClassAccessFlag::Final,
        ClassAccessFlag::Super,
        ClassAccessFlag::Interface,
        ClassAccessFlag::Abstract,
        ClassAccessFlag::Synthetic,
        ClassAccessFlag::Annotation,
        ClassAccessFlag::Enum,
        ClassAccessFlag::Constructor,
        ClassAccessFlag::ClassIsProxy,
    ];
    all.iter().filter(|&&f| raw & (f as u32) != 0).copied().collect()
}

/// Parse a raw u32 bitfield into a list of FieldAccessFlag values.
pub fn parse_field_access_flags(raw: u32) -> Vec<FieldAccessFlag> {
    let all = [
        FieldAccessFlag::Public,
        FieldAccessFlag::Private,
        FieldAccessFlag::Protected,
        FieldAccessFlag::Static,
        FieldAccessFlag::Final,
        FieldAccessFlag::Volatile,
        FieldAccessFlag::Synthetic,
        FieldAccessFlag::Enum,
        FieldAccessFlag::Constructor,
        FieldAccessFlag::DeclaredSynchronized,
    ];
    all.iter().filter(|&&f| raw & (f as u32) != 0).copied().collect()
}
