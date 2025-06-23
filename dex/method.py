from __future__ import annotations

from typing import BinaryIO

from dex import vlq_base128_le
from dex.dex import Dex

from dex.instructions import *

from dex.access_flags import Method_AccessFlags
from dex.helpers import b2i

from vm.utils import LogHandler

handler = LogHandler()
log = logging.getLogger(__name__)
log.addHandler(handler)
log.setLevel(logging.DEBUG)

def parse_access_flags(raw_access_flags):
    print(f"Starting aflag: {raw_access_flags}")
    parsed_access_flags = []
    for aflag in Method_AccessFlags:
        if raw_access_flags and isinstance(raw_access_flags, int):
            if aflag.value & raw_access_flags:
                parsed_access_flags.append(aflag)
                raw_access_flags -= aflag.value
                print(f"a_flags: {parsed_access_flags}, raw_flag: {raw_access_flags}")

    return parsed_access_flags


class Method:
    def __init__(self, curr_idx: int, e_method: Dex.EncodedMethod, dex):
        self.dex = dex
        self.fd = dex.fd
        current_method: Dex.EncodedMethod = e_method

        self.mthd_idx = curr_idx

        self.clazz_name = self.dex.dex.method_ids[curr_idx].class_name
        self.method_name = self.dex.dex.method_ids[curr_idx].method_name
        self.signature = f"{self.clazz_name}->{self.method_name}"
        self.params = self.dex.dex.method_ids[curr_idx].proto_desc
        self.return_type = ""
        self.annotations = []
        self.param_annotations = []
        self.access_flags = e_method.access_flags if type(e_method.access_flags) else parse_access_flags(e_method.access_flags)
        # self.access_flags = get_method_access_flags(e_method.access_flags)

        self.code_offset_val = current_method.code_off.value

        # If the code offset value is zero, the method is either abstract or native
        if self.code_offset_val != 0:

            self.fd.seek(self.code_offset_val)

            # From code_item
            self.registers_size: int = b2i(self.dex.fd.read(2))
            self.ins_size: int = b2i(self.dex.fd.read(2))
            self.outs_size: int = b2i(self.dex.fd.read(2))
            self.tries_size: int = b2i(self.dex.fd.read(2))
            self.debug_offset: int = b2i(self.dex.fd.read(4))
            self.instr_size: int = b2i(self.dex.fd.read(4))
            self.do_branching: bool = True

            # Prepopulate the registers to prevent size issues later
            self.registers = [None] * self.registers_size

            self.method_entrypoint_address = self.fd.tell()
            self.instructions = []
            self.tries = []
            self.handlers = []

            # Parse and store the instructions
            self.__parse_instructions()

            # If any try-catch statements exists, lets populate them
            if self.tries_size > 0:
                if self.instr_size % 2 == 0:
                    self.padding = b2i(self.dex.fd.read(2))
                self.__parse_tries_statements()


    def execute_method(self, memory):
        for instruction in self.instructions:
            instruction.execute(memory, self.registers)

    def is_native(self):
        if Method_AccessFlags.NATIVE in self.access_flags:
            return True
        return False

    def is_abstract(self):
        if Method_AccessFlags.ABSTRACT in self.access_flags:
            return True
        return False

    def print_registers(self) -> None:
        msg = ""
        for i in range(len(self.registers)):
            if isinstance(self.registers[i], list):
                if len(self.registers[i]) > 0 and isinstance(self.registers[i][0], bytes):
                    msg += ("v%s:%s+ " % (i, self.registers[i][0][0:8]))
                elif len(self.registers[i]) > 0:
                    msg += ("v%s:%s+ " % (i, self.registers[i][0:8]))
                else:
                    msg += ("v%s:%s " % (i, self.registers[i]))
            else:
                msg += ("v%s:%s " % (i, self.registers[i]))
        # log.debug(msg)

    def __parse_instructions(self):
        # Have to keep this like the below until the Instructions class can be rewritten
        while (self.fd.tell() - self.method_entrypoint_address) < self.instr_size * 2:
            instruction = self.__parse_single_instruction()

            if not instruction:
                break

            instruction.fetch()
            instruction.decode(self.fd)
            self.instructions.append(instruction)
            instruction.print_instruction()

    def __parse_tries_statements(self):
        while (self.fd.tell() - self.tries_entrypoint_address) < self.tries_size * 2:
            try_item = TryItem()
            try_item.fetch(self.fd)
            self.tries.append(try_item)

        catch_handler_list = EncodedCatchHandlerList()
        catch_handler_list.fetch(self.fd, self.dex)
        self.handlers = [tc for tc in catch_handler_list.handler_list]

    def __parse_single_instruction(self):
        opcode = b2i(self.fd.read(1))

        match opcode:
            case 0x00:  # NOP

                # pc = self.fd.tell()
                next_opcode = b2i(self.fd.read(1))

                match next_opcode:
                    # Packed-Switch-Data
                    case 0x01:
                        num_elements = b2i(self.fd.read(2))
                        _elements_base = b2i(self.fd.read(1))
                        _data = self.fd.read(4 * num_elements)
                        return Nop(0x0)  # Placeholder for now

                    # Sparse-Switch-Data
                    case 0x02:
                        num_elements = b2i(self.fd.read(2))
                        _data = self.fd.read(4 * num_elements * 2)

                        return Nop(0x0)  # Placeholder for now

                    # Fill-Array-Data
                    case 0x03:
                        b_per_element = b2i(self.fd.read(2))
                        num_elements = b2i(self.fd.read(4))
                        _data = self.fd.read(b_per_element * num_elements)

                        return Nop(0x0)  # Placeholder for now

                    case _:
                        self.fd.read(1)  # move to the format pos (needed for continued flow)
                        return Nop(0x0)

            case opcode if 0x01 <= opcode <= 0x09: return Move(opcode)
            case opcode if 0x0a <= opcode <= 0x0d: return MoveResult(opcode)
            case opcode if 0x0e <= opcode <= 0x11: return Return(opcode)
            case opcode if 0x12 <= opcode <= 0x1c: return Const(opcode)
            case opcode if 0x1d <= opcode <= 0x1e: return Monitor(opcode)

            case opcode if opcode == 0x1f: return CheckCast(opcode)
            case opcode if opcode == 0x20: return InstanceOf(opcode)
            case opcode if opcode == 0x21: return ArrLength(opcode)
            case opcode if opcode == 0x22: return NewInstance(opcode)

            case opcode if 0x23 <= opcode <= 0x26: return Array(opcode)

            case opcode if opcode == 0x27: return Throw(opcode)

            case opcode if 0x28 <= opcode <= 0x2a: return Goto(opcode)
            case opcode if 0x2b <= opcode <= 0x2c: return Switch(opcode)
            case opcode if 0x2d <= opcode <= 0x31: return Cmp(opcode)
            case opcode if 0x32 <= opcode <= 0x37: return If(opcode)
            case opcode if 0x38 <= opcode <= 0x3d: return IfZ(opcode)
            case opcode if 0x44 <= opcode <= 0x51: return ArrayOp(opcode)
            case opcode if 0x52 <= opcode <= 0x5f: return IOp(opcode)
            case opcode if 0x60 <= opcode <= 0x66: return SGet(opcode)
            case opcode if 0x67 <= opcode <= 0x6d: return SPut(opcode)
            case opcode if 0x6e <= opcode <= 0x72: return InvokeKind(opcode)
            case opcode if 0x74 <= opcode <= 0x78: return InvokeKindRange(opcode)
            case opcode if 0x7b <= opcode <= 0x8f: return UnOp(opcode)
            case opcode if 0x90 <= opcode <= 0xaf: return BinOp(opcode)
            case opcode if 0xb0 <= opcode <= 0xcf: return BinOp2Addr(opcode)
            case opcode if 0xd0 <= opcode <= 0xe2: return BinOpLit(opcode)
            case opcode if 0xe3 <= opcode <= 0xf9: pass

            case opcode if 0xfa: pass # invoke-polymorphic (not implemented yet)
            case opcode if 0xfb: pass # invoke-polymorphic/range (not implemented yet)
            case opcode if 0xfc: pass # invoke-custom (not implemented yet)
            case opcode if 0xfd: pass # invoke-custom/range (not implemented yet)
            case opcode if 0xfe: pass # const-method-handle (not implemented yet)
            case opcode if 0xff: pass # const-method-type (not implemented yet)

            case _:
                raise OpCodeNotFoundError(opcode)

class TryItem:
    def __init__(self):
        self.start_addr = 0
        self.insn_count = 0
        self.handler_offset = 0
        self.handler = None

    def fetch(self, fd: BinaryIO):
        self.start_addr = b2i(fd.read(4))
        self.insn_count = b2i(fd.read(2))
        self.handler_offset = b2i(fd.read(2))

class EncodedCatchHandler:
    def __init__(self):
        self.size = 0
        self.handlers = []
        self.catch_all_addr = 0
        self.is_negative = False

    def fetch(self, fd: BinaryIO, dex):
        self.size = vlq_base128_le.VlqBase128Le(fd).value
        self.is_negative = True if self.size > 0 else False

        # Let's make sure we make the size always positive from this point on
        if self.is_negative:
            self.size *= -1

        for i in range(self.size * -2):
            self.handlers.append({
                'type_id': dex.type_ids[vlq_base128_le.VlqBase128Le(fd).value],
                'addr': vlq_base128_le.VlqBase128Le(fd).value
            })

        # if negative, there will be a catch_all handler
        if self.is_negative:
            self.catch_all_addr = vlq_base128_le.VlqBase128Le(fd).value



class EncodedCatchHandlerList:
    def __init__(self):
        self.size = 0
        self.handler_list = []

    def fetch(self, fd: BinaryIO, dex):
        self.size = vlq_base128_le.VlqBase128Le(fd).value

        while fd.tell() < ( self.size * 2 ):
            catchHandler = EncodedCatchHandler()
            catchHandler.fetch(fd, dex)
            self.handler_list.append(catchHandler)

