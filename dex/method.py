from __future__ import annotations

import enum
import logging
from typing import BinaryIO

from fontTools.ttLib.tables.ttProgram import instructions
from kaitaistruct import KaitaiStream

import dex.instructions
from dex import vlq_base128_le
from dex.code_block import CodeBlock

from dex.instructions_new import *

from dex.access_flags import Method_AccessFlags
from dex.dex import Dex
from dex.helpers import b2i

from vm.utils import LogHandler

handler = LogHandler()
log = logging.getLogger(__name__)
log.addHandler(handler)
log.setLevel(logging.DEBUG)

class MethodType(enum.Enum):
    VIRTUAL = 0
    DIRECT = 1


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
    def __init__(self, curr_idx: int, e_method: Dex.EncodedMethod, method_type: MethodType, dex):
        self.dex = dex
        self.fd = dex.fd
        self.encoded_method = e_method
        self.method_type = method_type

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

        self.code_offset_val = self.encoded_method.code_off.value

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

            self.code_block: CodeBlock

            # Parse and store the instructions
            self.__parse_instructions()

            # If any try-catch statements exists, lets populate them
            if self.tries_size > 0:
                if self.instr_size % 2 == 0:
                    self.padding = b2i(self.dex.fd.read(2))
                self.tries_entrypoint_address = self.fd.tell()
                self.__parse_tries_statements()

            # Should be last so that anything with setting the tries doesn't get messed up
            self.__build_code_blocks()


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
        insns_start_offset = self.fd.tell()
        codepoint = 0

        while codepoint < self.instr_size:
            instruction = self.__parse_single_instruction()

            # Safety check
            if not instruction:
                break

            instruction.fetch()
            instruction.decode(self.fd)

            self.instructions.append(instruction)
            # instruction.code_block = codepoint
            codepoint = instruction.codepoint + instruction.width
            instruction.print_instruction()


        # Have to keep this like the below until the Instructions class can be rewritten
        # while (self.fd.tell() - self.method_entrypoint_address) < self.instr_size * 2:
        #     instruction = self.__parse_single_instruction()
        #
        #     if not instruction:
        #         break
        #
        #     instruction.fetch()
        #     instruction.decode(self.fd)
        #     self.instructions.append(instruction)
        #     instruction.print_instruction()


    def __build_code_blocks(self):
        # log.debug(f"Building code blocks for {self.clazz_name}->{self.method_name}")
        self.code_block = CodeBlock(self)
        self.code_block.build_code_flow()

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

        match opcode: # Will always be in the format: opcode (1 byte), fmt (1 byte)
            case 0x00:
                # The other payload formats have been put under the relevant instructions rather than under "NOP"
                # includes: 0x0100, 0x0200, 0x0300
                return Nop(opcode, self.dex)
            case opcode if 0x01 <= opcode <= 0x09: return Move(opcode, self.dex)
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
            case opcode if 0x52 <= opcode <= 0x58: return IGet(opcode)
            case opcode if 0x59 <= opcode <= 0x5f: return IPut(opcode)
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
        self.size = vlq_base128_le.VlqBase128Le(fd)
        self.is_negative = True if self.size > 0 else False

        # Let's make sure we make the size always positive from this point on
        if self.is_negative:
            self.size *= -1

        for i in range(self.size * -2):
            self.handlers.append({
                'type_id': dex.type_ids[vlq_base128_le.VlqBase128Le(KaitaiStream(fd))],
                'addr': vlq_base128_le.VlqBase128Le(KaitaiStream(fd))
            })

        # if negative, there will be a catch_all handler
        if self.is_negative:
            self.catch_all_addr = vlq_base128_le.VlqBase128Le(KaitaiStream(fd))



class EncodedCatchHandlerList:
    def __init__(self):
        self.size = 0
        self.handler_list = []

    def fetch(self, fd: BinaryIO, dex):
        self.size = vlq_base128_le.VlqBase128Le(KaitaiStream(fd))

        while fd.tell() < ( self.size.value * 2 ):
            catchHandler = EncodedCatchHandler()
            catchHandler.fetch(fd, dex)
            self.handler_list.append(catchHandler)
