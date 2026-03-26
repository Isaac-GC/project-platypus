import enum
import logging
from typing import BinaryIO

from dex.access_flags import Class_AccessFlags
from dex.annotation import Annotation
from dex.dex import Dex
from dex.field import Field
from dex.method import Method, MethodType
from vm.utils import LogHandler

from dex.vlq_base128_le import VlqBase128Le

handler = LogHandler()
log = logging.getLogger(__name__)
log.addHandler(handler)
log.setLevel(logging.DEBUG)

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

            if class_def.annotations_off:
                self.annotations = Annotation(self.dex.fd, self.dex, class_def.annotations_off)

    def __parse_methods(self):
        curr_idx = 0
        for virtual_method in self.class_data.virtual_methods:
            if not curr_idx:
                curr_idx = virtual_method.method_idx_diff.value
            else:
                curr_idx += virtual_method.method_idx_diff.value

            self.methods.append(Method(curr_idx, virtual_method, MethodType.VIRTUAL, self.dex))

        curr_idx = 0
        for direct_method in self.class_data.direct_methods:
            if not curr_idx:
                curr_idx = direct_method.method_idx_diff.value
            else:
                curr_idx += direct_method.method_idx_diff.value

            self.methods.append(Method(curr_idx, direct_method, MethodType.DIRECT, self.dex))

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