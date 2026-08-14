import enum
from typing import BinaryIO

from kaitaistruct import KaitaiStream

from dex.helpers import b2i
from dex.vlq_base128_le import VlqBase128Le

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


class Annotation:

    def __init__(self, cursor, dex_file_reference, annotations_offset):
        self.value: str = ""
        self.dex = dex_file_reference.dex
        self.cursor = cursor
        self.annotations_offset: int = annotations_offset

        class_annotations_offset = self.cursor.read(4)
        fields_size = self.cursor.read(4)
        annotated_methods_size = self.cursor.read(4)
        annotated_parameters_size = self.cursor.read(4)
        self.class_annotations = []
        self.field_annotations = []
        self.method_annotations = []
        self.parameters_annotations = []

    def _parse_annotations(self,):
        self.dex.seek(self.annotations_offset)
        class_annotations_offset = self.cursor.read(4)
        fields_size = self.cursor.read(4)
        annotated_methods_size = self.cursor.read(4)
        annotated_parameters_size = self.cursor.read(4)

        if class_annotations_offset:
            self.class_annotations = self._parse_annotation_set(class_annotations_offset)

        for _ in range(fields_size):
            field_idx = b2i(self.cursor.read(4))
            annotations_offset = b2i(self.cursor.read(4))
            field = self.dex.fields[field_idx]
            if field and annotations_offset:
                self.field_annotations = self._parse_annotation_set(annotations_offset)

        for _ in range(annotated_methods_size):
            method_idx = b2i(self.cursor.read(4))
            annotations_offset = b2i(self.cursor.read(4))
            method = self.dex.methods[method_idx]
            if method and annotations_offset:
                self.method_annotations = self._parse_annotation_set(annotations_offset)

        for _ in range(annotated_parameters_size):
            method_idx = b2i(self.cursor.read(4))
            annotations_offset = b2i(self.cursor.read(4))
            method = self.dex.methods[method_idx]
            if method and annotations_offset:
                self.parameters_annotations = self._parse_annotation_set(annotations_offset)


    def _parse_annotation_set(self, offset):
        curr_pos = self.cursor.tell()
        self.cursor.seek(offset)

        size = b2i(self.cursor.read(4))
        annotations = [] # Temp placeholder (real objects will be moved)

        for _ in range(size):
            annotation_offset = self.cursor.read(4)
            annotations.append(self._parse_annotation_item(annotation_offset))

        self.cursor.seek(curr_pos) # Return cursor to original position
        return annotations

    def _parse_annotation_item(self, offset):
        curr_pos = self.cursor.tell()
        self.cursor.seek(offset)

        visibilty = self.cursor.read(1)
        encoded_annotation = self._parse_encoded_annotation()

        self.cursor.seek(curr_pos)
        return {
            'visibility': visibilty,
            'encoded_annotation': encoded_annotation,
        }

    def _parse_encoded_annotation(self):
        type_idx = VlqBase128Le(KaitaiStream(self.cursor))
        size = b2i(VlqBase128Le(KaitaiStream(self.cursor)))

        elements = {}
        for _ in range(size):
            name_idx = VlqBase128Le(KaitaiStream(self.cursor))
            name = self.dex.string_ids[name_idx].value.raw_data
            value = self.parse_encoded_value()
            elements[name] = value

    def parse_encoded_value(self):
        value_arg_type = b2i(self.cursor.read(1))
        value_type = value_arg_type & 0x1F
        value_arg  = (value_arg_type >> 5) & 0x07

        size = value_arg_type + 1

        match value_type:
            case ValueFormats.BYTE.value:
                return b2i(self.cursor.read(1))

            case ValueFormats.SHORT.value:
                return b2i(self.cursor.read(size))

            case ValueFormats.CHAR.value:
                return b2i(self.cursor.read(size))

            case ValueFormats.INT.value:
                return b2i(self.cursor.read(size))

            case ValueFormats.LONG.value:
                return b2i(self.cursor.read(size))

            case ValueFormats.FLOAT.value:
                import struct
                raw = self.cursor.read(size)
                return struct.unpack('<f', raw.ljust(4, b'\x00'))[0]

            case ValueFormats.DOUBLE.value:
                import struct
                raw = self.cursor.read(size)
                return struct.unpack('<d', raw.ljust(8, b'\x00'))[0]

            case ValueFormats.STRING.value:
                string_idx = b2i(self.cursor.read(size))
                return self.dex.string_ids[string_idx].value.raw_data

            case ValueFormats.TYPE.value:
                type_idx = b2i(self.cursor.read(size))
                return self.dex.type_ids[type_idx].type_name

            case ValueFormats.FIELD.value:
                field_idx = b2i(self.cursor.read(size))
                return self.dex.field_ids[field_idx]

            case ValueFormats.METHOD.value:
                method_idx = b2i(self.cursor.read(size))
                return self.dex.method_ids[method_idx]

            case ValueFormats.ENUM.value:
                field_idx = b2i(self.cursor.read(size))
                return self.dex.field_ids[field_idx]

            case ValueFormats.ARRAY.value:
                return self._parse_encoded_array()

            case ValueFormats.ANNOTATION.value:
                return self._parse_encoded_annotation()

            case ValueFormats.NULL.value:
                return None

            case ValueFormats.BOOLEAN.value:
                return bool(value_arg)

            case _:
                return self.cursor.read(size)


    def _parse_encoded_array(self):
        size = b2i(VlqBase128Le(KaitaiStream(self.cursor)))
        return [self._parse_encoded_annotation() for _ in range(size)]

    def _parse_annotation_set_ref_list(self, offset):
        curr_pos = self.cursor.tell()
        self.cursor.seek(offset)

        size = b2i(self.cursor.read(4))
        param_annotations = []

        for _ in range(size):
            annotations_offset = b2i(self.cursor.read(4))
            if annotations_offset:
                param_annotations.append(self._parse_annotation_set(annotations_offset))
            else:
                param_annotations.append([])

        self.cursor.seek(curr_pos)
        return param_annotations
