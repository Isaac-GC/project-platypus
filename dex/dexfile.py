import hashlib
import io
import logging

from kaitaistruct import KaitaiStream

from dex import vlq_base128_le
from dex.clazz import Clazz
from dex.dex import Dex
from dex.helpers import b2i
from vm.utils import LogHandler

# from dex.instructions import InvokeKind, InvokeKindRange

handler = LogHandler()
log = logging.getLogger(__name__)
log.addHandler(handler)
log.setLevel(logging.DEBUG)

class CallSiteItem:
    def __init__(self):
        self.method_handle_idx: int
        self.method_name: str
        self.method_type = int
        self.arguments: list

class MethodHandleItem:
    def __init__(self):
        self.method_handle_type: int
        self.field_or_method_id: int


class DexFile:
    def __init__(self, dex_file_path):
        self.dex_file_path = dex_file_path
        self.dex = Dex.from_file(dex_file_path)

        # print("Loading dex from ", dex_file_path)
        with open(dex_file_path, 'rb') as fd:
            self.fd = io.BytesIO(fd.read())

        self.__get_dexfile_hash()
        self.classes_filename = dex_file_path.split('/')[-1]
        self.clazzes = []


        # Helper maps
        self.string_ids = self.dex.string_ids
        self.type_ids = self.dex.type_ids
        self.method_ids = self.dex.method_ids

        self.map_list: list[Dex.MapItem] = self.dex.map.list
        # self.class_site_items =

        self.lookup_map = {}
        self.lookup_by_id_map = {}

        self.__build_class_list()
        self.__build_lookup_map()
        # print(self.clazzes)
        # self.__convert_instance_calls_to_obj_ref()

    # def lookup_method_by_id(self, method_id):

    def lookup_class_by_id(self, some_class_id):
        log.debug(f"Looking up class id: {some_class_id}")

        for clazz in self.lookup_map:
            if clazz.class_id == some_class_id:
                return clazz

    def lookup_method(self, some_method_id):
        log.debug(f"Looking up method_id: {some_method_id}")

        # Try seeing if it's an already parsed method
        for clazz in self.lookup_map:
            for mthd in self.lookup_map[clazz]:
                if some_method_id == self.lookup_map[clazz][mthd].mthd_idx:
                    log.debug(f"Found method under class: {clazz} and method: {mthd}")
                    return self.lookup_map[clazz][mthd]

        # Backup method
        return some_method_id


    def __get_dexfile_hash(self):
        md = hashlib.sha256()
        md.update(self.fd.getbuffer())
        self.digest = md.hexdigest()

    def __build_class_list(self):
        for class_def in self.dex.class_defs:
            self.clazzes.append(Clazz(class_def, self))

    def __build_lookup_map(self):
        for clazz in self.clazzes:
            if clazz.class_name not in self.lookup_map:
                clazz_data = {}
                for mthd in clazz.methods:
                    self.lookup_by_id_map[mthd.mthd_idx] = mthd
                    if mthd.method_name not in clazz_data:
                        clazz_data[mthd.method_name] = mthd

                # TODO: Add logic to support static/instance fields
                self.lookup_map[clazz.class_name] = clazz_data

            else:
                log.debug(f"[-] Skipping adding {clazz.class_name}")

    def __build_call_site_items(self):
        for item in self.map_list:
            if item.type == 0x0007:
                self.fd.seek(item.offset)
                call_site_item_offset = b2i(self.fd.read(4))

                self.fd.seek(call_site_item_offset)

                stream = KaitaiStream(self.fd)
                size = vlq_base128_le.VlqBase128Le(stream).value
                call_site_item = CallSiteItem()

                encoded_array = []
                if size > 3:
                    for i in range(size):
                        hdr = b2i(self.fd.read(1))
                        _type = hdr & 0x1F
                        valArg = hdr << 5


                        match _type:
                            case 0x00: val = b2i(self.fd.read(1))
                            case 0x02: val = b2i(self.fd.read(2))
                            case 0x03: val = b2i(self.fd.read(2))
                            case 0x04: val = b2i(self.fd.read(4))
                            case 0x06: val = b2i(self.fd.read(8))
                            case 0x10: val = b2i(self.fd.read(4))
                            case 0x11: val = b2i(self.fd.read(8))
                            case 0x15: val = b2i(self.fd.read(4))
                            case 0x16: val = b2i(self.fd.read(4))
                            case 0x17: val = b2i(self.fd.read(4))
                            case 0x18: val = b2i(self.fd.read(4))
                            case 0x19: val = b2i(self.fd.read(4))
                            case 0x1a: val = b2i(self.fd.read(4))
                            case 0x1b: val = b2i(self.fd.read(4))
                            case 0x1c: val = None # Change this to actually get encoded items
                            case 0x1d: val = b2i(self.fd.read(1))
                            case 0x1e: val = None
                            case 0x1f: val = valArg != 0


    # def __convert_instance_calls_to_obj_ref(self):
    #     for clazz in self.clazzes:
    #         for method in clazz.methods:
    #             if method.instructions and len(method.instructions) != 0:
    #                 for instr in method.instructions:
    #                     if isinstance(instr, InvokeKind):
    #                         instr.method_reference = self.lookup_by_id_map[instr.vB]
    #                     elif isinstance(instr, InvokeKindRange):
    #                         instr.method_reference = self.lookup_by_id_map[instr.vB]
