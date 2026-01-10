import enum
import logging
from typing import BinaryIO

from dex.access_flags import Class_AccessFlags
from dex.dex import Dex
from dex.field import Field
from dex.method import Method
from vm.utils import LogHandler

from vlq_base128_le import VlqBase128Le

handler = LogHandler()
log = logging.getLogger(__name__)
log.addHandler(handler)
log.setLevel(logging.DEBUG)

class ValueFormats(enum.Enum):
    BYTE   = 0x00
    SHORT  = 0x02
    CHAR   = 0x03
    INT    = 0x04
    LONG   = 0x06
    FLOAT  = 0x10
    DOUBLE = 0x11
    METHOD_TYPE   = 0x15
    METHOD_HANDLE = 0x16
    STRING = 0x17
    TYPE   = 0x18
    FIELD  = 0x19
    METHOD = 0x1A
    ENUM   = 0x1B
    ARRAY  = 0x1C
    ANNOTATION = 0x1D
    NULL    = 0x1E
    BOOLEAN = 0x1F

def parse_access_flags(raw_access_flags):
    print(f"Starting aflag: {raw_access_flags}")
    parsed_access_flags = []
    for aflag in Class_AccessFlags:
        if raw_access_flags and isinstance(raw_access_flags, int):
            if aflag.value & raw_access_flags:
                parsed_access_flags.append(aflag)
                raw_access_flags -= aflag.value
                print(f"a_flags: {parsed_access_flags}, raw_flag: {raw_access_flags}")

    return parsed_access_flags


class Clazz:
    def __init__(self, class_def: Dex.ClassDefItem, dex):
        self.dex = dex

        self.class_def = class_def
        self.class_id = class_def.class_idx
        self.class_name = class_def.type_name
        self.methods: list[Method] = []

        # TODO: implement later
        self.interfaces = []
        self.static_fields = []
        self.instance_fields = []
        self.annotations = []

        self.access_flags = class_def.access_flags if type(class_def.access_flags) else parse_access_flags(class_def.access_flags)
        # print(f"\nCalling class name: {self.class_name}\nAccess Flags: {self.access_flags}")
        # if len(self.access_flags) == 0:
        #     parse_access_flags(class_def.access_flags)

        # Sometimes but not always present
        self.superclass = None

        self.source_file = ""
        self.signature = ""

        if class_def.class_data:
            self.class_data = class_def.class_data
            self.__parse_methods()
            self.__parse_fields()

    def __parse_methods(self):
        curr_idx = 0
        for virtual_method in self.class_data.virtual_methods:
            if not curr_idx:
                curr_idx = virtual_method.method_idx_diff.value
            else:
                curr_idx += virtual_method.method_idx_diff.value

            self.methods.append(Method(curr_idx, virtual_method, self.dex))

        curr_idx = 0
        for direct_method in self.class_data.direct_methods:
            if not curr_idx:
                curr_idx = direct_method.method_idx_diff.value
            else:
                curr_idx += direct_method.method_idx_diff.value

            self.methods.append(Method(curr_idx, direct_method, self.dex))

    def __parse_fields(self):
        curr_idx = 0
        for static_field in self.class_data.static_fields:
            if not curr_idx:
                curr_idx = static_field.field_idx_diff.value
            else:
                curr_idx += static_field.field_idx_diff.value

            self.static_fields.append(Field(curr_idx, static_field, self.dex))


        curr_idx = 0
        for instance_field in self.class_data.instance_fields:
            if not curr_idx:
                curr_idx = instance_field.field_idx_diff.value
            else:
                curr_idx += instance_field.field_idx_diff.value

            self.static_fields.append(Field(curr_idx, instance_field, self.dex))

    def __parse_annotations(self):
       annotations_offset = self.class_def.annotations_off
       curr_pos = self.dex.fd
       cursor: BinaryIO = self.dex.fd.seek(annotations_offset)

       class_annotations_offset = cursor.read(4)
       fields_size = cursor.read(4)
       annotated_methods_size = cursor.read(4)
       annotated_parameters_size = cursor.read(4)
       field_annotations = []
       method_annotations = []
       parameters_annotations = []

    def __parse_field_annotations(self, fd: BinaryIO):
        field_idx = fd.read(4)
        annotations_offset = fd.read(4)
        annotation_item = self.__parse_annotation_set_item(annotations_offset, fd)

    def __parse_method_annotations(self, fd: BinaryIO):
        method_idx = fd.read(4)
        annotations_offset = fd.read(4)
        annotation_item = self.__parse_annotation_set_item(annotations_offset, fd)

    def __parse_parameter_annotations(self, fd: BinaryIO):
        method_idx = fd.read(4)
        annotations_offset = fd.read(4)
        annotation_set_ref = self.__parse_annotation_set_ref_list(annotations_offset, fd)

    def __parse_annotation_set_ref_list(self, item_offset, fd: BinaryIO):
        size = fd.read(4)
        annotation_set_ref_items = []

    def __parse_annotation_set_item(self, item_offset, fd: BinaryIO):
        annotation_offset = fd.read(4)
        size

    def __parse_encoded_annotation(self, item_offset, fd: BinaryIO):
        type_idx = VlqBase128Le(fd)
        size = VlqBase128Le(fd)
        elements = []
        for _ in range(size.value):
            name_idx = VlqBase128Le(fd)
            value = encod

    def __parse_encoded_value(self, raw_value):
        value_type = raw_value & 0x1F
        value_arg = (raw_value >> 5) & 0x07

         match value_type:
             case 0x17:
                return ValueFormats.METHOD_HANDLE
            case 0x18

        match
        value_type
        {
            0x17 = > { // METHOD_HANDLE
        let
        handle_idx = cursor.read_u16()?;
        Ok(EncodedValue::MethodHandle(handle_idx))
        }
        0x18 = > { // METHOD_TYPE
        let
        type_idx = cursor.read_u16()?;
        Ok(EncodedValue::Type(type_idx))
        }
        0x17 = > { // STRING
        let
        string_idx = cursor.read_u32()?;
        Ok(EncodedValue::String(string_idx))
        }
        0x00 = > { // BYTE
        let
        byte_val = cursor.read_u8()?;
        Ok(EncodedValue::Byte(byte_val))
        }
        0x02 = > { // SHORT
        let
        short_val = cursor.read_u16()?;
        Ok(EncodedValue::Short(short_val))
        }
        0x03 = > { // CHAR
        let
        char_val = cursor.read_u16()?;
        Ok(EncodedValue::Char(char_val))
        }
        0x04 = > { // INT
        let
        int_val = cursor.read_u32()?;
        Ok(EncodedValue::Int(int_val))
        }
        0x06 = > { // LONG
        let
        long_val = cursor.read_u64()?;
        Ok(EncodedValue::Long(long_val))
        }
        _ = > {
              // For
        unsupported
        types,
        return a
        generic
        value
        Ok(EncodedValue::Null)
        }
        }
        }

