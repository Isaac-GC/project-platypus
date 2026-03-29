from enum import Enum

class Method_AccessFlags(Enum):
    PUBLIC = 0x1
    PRIVATE = 0x2
    PROTECTED = 0x4
    STATIC = 0x8
    FINAL = 0x10
    SYNCHRONIZED = 0x20
    BRIDGE = 0x40
    VARARGS = 0x0080
    NATIVE = 0x0100
    ABSTRACT = 0x0400
    STRICT = 0x0800
    SYNTHETIC = 0x1000
    CONSTRUCTOR = 0x10000
    DECLARED_SYNCHRONIZED = 0x20000

class Class_AccessFlags(Enum):
    PUBLIC = 0x1
    PRIVATE = 0x2
    PROTECTED = 0x4
    STATIC = 0x8
    FINAL = 0x10
    SUPER = 0x20
    INTERFACE = 0x0200
    ABSTRACT = 0x0400
    SYNTHETIC = 0x1000
    ANNOTATION = 0x2000
    ENUM = 0x4000
    CONSTRUCTOR = 0x10000
    CLASS_IS_PROXY = 0x40000

class Field_AccessFlags(Enum):
    PUBLIC = 0x1
    PRIVATE = 0x2
    PROTECTED = 0x4
    STATIC = 0x8
    FINAL = 0x10
    VOLATILE = 0x40
    SYNTHETIC = 0x1000
    ENUM = 0x4000
    CONSTRUCTOR = 0x10000
    DECLARED_SYNCHRONIZED = 0x20000


def parse_access_flags(raw_access_flags, access_flags_type):
    if isinstance(raw_access_flags, list):
        return raw_access_flags

    value = raw_access_flags.value if hasattr(raw_access_flags, "value") else raw_access_flags
    if not isinstance(value, int):
        return []

    parsed_access_flags = []
    for flag in access_flags_type:
        if value and flag.value & value:
            parsed_access_flags.append(flag)
            value -= flag.value

    return parsed_access_flags

def parse_method_access_flags(raw_access_flags):
    return parse_access_flags(raw_access_flags, Method_AccessFlags)

def parse_clazz_access_flags(raw_access_flags):
    return parse_access_flags(raw_access_flags, Class_AccessFlags)