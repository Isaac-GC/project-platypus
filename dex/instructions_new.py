import logging
import struct
from enum import Enum
from typing import BinaryIO

from codegen.opcode_helper import OPCODE_WIDTH
from dex.helpers import b2i, nibble_at, twos_complement, sign_extend
from vm.call_site_resolver import CallSiteResolver
from vm.utils import LogHandler

handler = LogHandler()
log = logging.getLogger(__name__)
log.addHandler(handler)
log.setLevel(logging.INFO)
# log.setLevel(logging.DEBUG)

MODIFIER_TYPE_LOOKUP = ["", "-wide", "-object", "-boolean", "-byte", "-char", "-short"]
INVOKE_TYPE_LOOKUP = ["-virtual", "-super", "-direct", "-static", "-interface"]

BIN_OPERATOR_LOOKUP = ["add", "sub", "mul", "div", "rem", "and", "or", "xor", "shl", "shr", "ushr"]
BIN_OPERAND_LOOKUP = ["int", "long", "float", "double"]

# Used for Binary Op-type instructions
def reg_ops_helper(operator_type, operand_type, b, c):
    a = 0

    match operator_type:
        case 0x0: a = b + c
        case 0x1: a = b - c
        case 0x2: a = b * c
        case 0x3:
            try:
                a = b // c
            except ZeroDivisionError as ze:
                a = 0

        case 0x4: a = b % c
        case 0x5: a = b & c
        case 0x6: a = b | c
        case 0x7: a = b ^ c
        case 0x8:
            if operand_type == 0x1:
                BIT_BACK = 0xFFFFFFFFFFFFFFFF
                c = c % 64
            else:
                c = c % 32
                BIT_BACK = 0xFFFFFF
            a = (b << c) & BIT_BACK

        case 0x9:
            if operand_type == 0x1:
                BIT_BACK = 0xFFFFFFFFFFFFFFFF
                c = c % 64
            else:
                c = c % 32
                BIT_BACK = 0xFFFFFF
            a = (b >> c) & BIT_BACK

        case 0xa:
            if operand_type == 0x1:
                BIT_BACK = 0xFFFFFFFFFFFFFFFF
                c = c % 64
            else:
                c = c % 32
                BIT_BACK = 0xFFFFFF

            shift = b % (1 << 32)
            if operand_type == 0x0:
                a = (shift >> c) & BIT_BACK
            else:
                a = (shift << c) & BIT_BACK

    # an 'int' (in Java) should be 32 bits
    if operand_type == 0x0:
        a = int(a) & 0xFFFFFFFF
        if a > 0x7FFFFFFF:
            a -= 0xFFFFFFFF - 1

    # Otherwise: a 'long', 'float', and 'double' is always 64 bits
    #    This includes the "two and one" register value retrieval edge case for 'long'
    else:
        a = int(a) & 0xFFFFFFFFFFFFFFFF
        if a > 0x7FFFFFFFFFFFFFFF:
            a -= 0xFFFFFFFFFFFFFFFF - 1

    return a


class ControlFlow(Enum):
    Terminate = 0x1
    GoTo = 0x2
    Branch = 0x3
    FallThrough = 0x4

class OpCodeNotFoundError(Exception):
    def __init__(self, opcode):
        super().__init__(f"{hex(opcode)} not defined, try another decoder")

class InstructionReturn:
    def __init__(self, ret, is_external_call, parameters):
        self.ret = ret
        self.is_external_call = is_external_call
        self.parameters = parameters

class InstructionBase:

    def __init__(self, opcode, dex):
        self.address: int = 0
        self.fmt: str     = '00x' # set default fmt to the one for unused opcodes
        self.opcode: int  = opcode
        self.operands: list[int] = []

        self.codepoint: int = 0

        self.prefix: str = "nop"
        self.suffix: str = ""

        self.instruction_str: str = ""

        # Used for dex file reference (annoying, but needed for lookups)
        self.dex = dex

        self.control_flow = ControlFlow.FallThrough

        # used by some instructions
        self.operator_type = 0
        self.operand_type = 0

        # Only used for NOP types and the contained payload formats
        self.nop_data = {}

        # Method Registers (Pre-staging)
        # Corresponds to Dalvik Instruction Formats
        # Ref: https://source.android.com/docs/core/runtime/instruction-formats
        self.vA = None
        self.vB = None
        self.vC = None
        self.vD = None
        self.vE = None
        self.vF = None
        self.vG = None
        self.vH = None

        self.vZ = None # "Null" or a not important byte

    def fetch(self) -> None:
        raise NotImplementedError()

    def decode_args(self, fd: BinaryIO):
        return self.decode_args_by_format(fd)

    def print_instruction(self):
        if self.instruction_str == "":
            raise NotImplementedError()
        else:
            log.debug(self.instruction_str)

    def decode_args_by_format(self, fd: BinaryIO):

        match self.fmt:
            case '10t':
                self.vA, = self._read(fd, '<b') # skip padding, vA signed

            case '10x':
                self.vZ, = self._read(fd, '<B')

            case '11n':
                lo, hi = self._nibbles(fd)
                self.vA = lo
                self.vB = hi if hi < 8 else hi - 16

            case '11x':
                self.vA, = self._read(fd, '<B')

            case '12x':
                self.vA, self.vB = self._nibbles(fd)

            case '20t':
                _, self.vA = self._read(fd, '<Bh') # skip padding, vA signed

            case '21c' | '21h' | '22x':
                self.vA, self.vB = self._read(fd, '<BH')

            case '21s' | '21t':
                self.vA, self.vB = self._read(fd, '<Bh') # 21t -> vB signed

            case '22b':
                self.vA, self.vB, self.vC = self._read(fd, '<BBb') # vC signed

            case '22c':
                self.vA, self.vB = self._nibbles(fd)
                self.vC, = self._read(fd, '<H')

            case '22s' | '22t':
                self.vA, self.vB = self._nibbles(fd)
                self.vC, = self._read(fd, '<h') # 22t -> vC signed

            case '23x':
                self.vA, self.vB, self.vC = self._read(fd, '<BBB')

            case '30t':
                _, self.vA = self._read(fd, '<Bi') # skip padding, vA signed

            case '31i' | '31t':
                self.vA, self.vB = self._read(fd, '<Bi') # vB signed

            case '31c':
                self.vA, self.vB = self._read(fd, '<BI')

            case '32x':
                _, self.vA, self.vB = self._read(fd, '<BHH')

            case '35c':
                self.vG, self.vA = self._nibbles(fd) # vA = count, vG is the last register
                self.vB, = self._read(fd, '<H') # method/type index
                self.vC, self.vD = self._nibbles(fd)
                self.vE, self.vF = self._nibbles(fd)

            case '3rc':
                self.vA, self.vB, self.vC = self._read(fd, '<BHH')

            case '51l':
                self.vA, self.vB = self._read(fd, '<Bq') # vB signed



    def execute(self, memory, registers):
        return InstructionReturn(1, False, [])

    @property
    def width(self) -> int:
        return OPCODE_WIDTH[self.opcode]

    @property
    def byte_size(self) -> int:
        return self.width * 2

    def _read(self, fd, fmt: str) -> tuple:
        size = struct.calcsize(fmt)
        data = fd.read(size)
        result = struct.unpack(fmt, data)
        return result

    def _nibbles(self, fd) -> tuple[int, int]:
        byte, = struct.unpack("<B", fd.read(1))
        return (byte & 0xF), (byte >> 4)

    def _build_operands(self):
        self.operands = [
            v for v in (self.vA, self.vB, self.vC, self.vD,
                        self.vE, self.vF, self.vG, self.vH)
            if v is not None
        ]

    def _safe_field(self, idx: int) -> str:
        try:
            field = self.dex.dex.field_ids[idx]
            return f"{field.class_name}->{field.field_name}:{field.type_name}"
        except IndexError:
            log.error(f"field_ids[{idx}] out of range at {self.address:#x}")
            return f"field@{idx}"

    def _safe_type(self, idx: int) -> str:
        try:
            return self.dex.dex.type_ids[idx].type_name
        except IndexError:
            log.error(f"type_ids[{idx}] out of range at {self.address:#x}")
            return f"type@{idx}"

    def _safe_method(self, idx: int) -> str:
        try:
            m = self.dex.dex.method_ids[idx]
            return f"{m.class_name}->{m.method_name}{m.proto_desc}"
        except IndexError:
            log.error(f"method_ids[{idx}] out of range at {self.address:#x}")
            return f"method@{idx}"

    def _safe_string(self, idx: int) -> str:
        try:
            raw = self.dex.dex.string_ids[idx].value.raw_data
            if isinstance(raw, bytes):
                return raw.decode('utf-8', errors='replace')
            return str(raw)
        except IndexError:
            log.error(f"string_ids[{idx}] out of range at {self.address:#x}")
            return f"string@{idx}"

class Nop(InstructionBase):

    def fetch(self) -> None:
        self.fmt = '10x'
        self._payload_width = None

    @property
    def width(self):
        if self._payload_width is not None:
            return self._payload_width
        return OPCODE_WIDTH[self.opcode]

    def decode(self, fd) -> None:
        self.address = fd.tell() - 1
        next_byte = fd.read(1)
        if not next_byte:
            self.instruction_str = "nop"
            self._build_operands()
            return

        match next_byte[0]:
            case 0x01:  # packed-switch-payload
                self._decode_packed_switch_payload(fd)
            case 0x02:  # sparse-switch-payload
                self._decode_sparse_switch_payload(fd)
            case 0x03:  # fill-array-data-payload
                self._decode_fill_array_data_payload(fd)
            case _:
                self.instruction_str = "nop"

        self._build_operands()

    def execute(self, memory, v):
        return super().execute(memory, v)

    def _decode_packed_switch_payload(self, fd):
        size, = self._read(fd, '<H')
        first_key, = self._read(fd, '<i')
        targets = [self._read(fd, '<i')[0] for _ in range(size)]
        self.nop_data = {
            'type': 'packed_switch',
            'size': size,
            'first_key': first_key,
            'targets': targets,
        }
        self._payload_width = 4 + (size * 2)
        self.instruction_str = f"; packed-switch-payload size={size}"

    def _decode_sparse_switch_payload(self, fd):
        size, = self._read(fd, '<H')
        keys    = [self._read(fd, '<i')[0] for _ in range(size)]
        targets = [self._read(fd, '<i')[0] for _ in range(size)]
        self.nop_data = {
            'type': 'sparse-switch',
            'size': size,
            'keys': keys,
            'targets': targets
        }
        self._payload_width = 2 + (size * 4)
        self.instruction_str = f"; sparse-switch-payload size={size}"

    def _decode_fill_array_data_payload(self, fd):
        element_width, = self._read(fd, '<H')
        element_count, = self._read(fd, '<I')
        data_bytes = element_width * element_count
        # Payload is padded to 4-byte (2 code unit) alignment
        padded = (data_bytes + 1) & ~1
        data = fd.read(padded)
        self.nop_data = {
            'type': 'fill-array-data',
            'element_width': element_width,
            'element_count': element_count,
            'data': data[:data_bytes]
        }
        self._payload_width = 4 + (padded // 2)
        self.instruction_str = f"; fill-array-data-payload elements={element_count} width={element_width}"


class Move(InstructionBase):

    def fetch(self) -> None:
        obj_type = ["", "-wide", "-object"]
        suffix_iter = (self.opcode // 3) % 3 # A value should not be larger than 2 in this
        self.prefix = f"move{obj_type[suffix_iter]}"

        match self.opcode:
            case 0x01 | 0x04 | 0x07:
                self.fmt = '12x'
            case 0x02 | 0x05 | 0x08:
                self.fmt = '22x'
                self.suffix = '/from16'
            case 0x03 | 0x06 | 0x09:
                self.fmt = '32x'
                self.suffix = "/16"
            case _:
                raise OpCodeNotFoundError(self.opcode)

    def decode(self, fd) -> None:
        self.address = fd.tell() - 1
        self.decode_args(fd)
        self.instruction_str = f"{self.prefix}{self.suffix} v{self.vA} v{self.vB}"
        self._build_operands()

    def execute(self, memory, registers):
        if self.opcode not in [0x04, 0x05, 0x06]: # wide instructions
            registers[self.vA] = registers[self.vB]
        else: # Do 'wide' move
            registers[self.vA] = registers[self.vB]
            registers[self.vA + 1] = registers[self.vB + 1]

        memory.last_return = self.vA


class MoveResult(InstructionBase):

    def fetch(self) -> None:
        self.fmt = '11x'

        match self.opcode:
            case 0x0a:
                self.prefix = "move-result"
            case 0x0b:
                self.prefix = "move-result-wide"
            case 0x0c:
                self.prefix = "move-result-object"
            case 0x0d:
                self.prefix = "move-exception"
            case _:
                raise OpCodeNotFoundError(self.opcode)

    def decode(self, fd):
        self.address = fd.tell() - 1
        self.decode_args(fd)
        self.instruction_str = f"{self.prefix} v{self.vA}"
        self._build_operands()

    def execute(self, memory, registers):
        if self.opcode == 0x0b: # if it's 'move-result-wide'
            try:
                registers[self.vA] = memory.last_return[0]
                registers[self.vA + 1] = memory.last_return[1]

            # Handle null returns
            except TypeError as te:
                registers[self.vA] = 0
                registers[self.vA + 1] = 0

        else:
            registers[self.vA] = memory.last_return

class Return(InstructionBase):

    def fetch(self) -> None:
        self.fmt = '11x'
        self.control_flow = ControlFlow.Terminate

        match self.opcode:
            case 0x0e:
                self.prefix = "return-void"
            case 0x0f:
                self.prefix = "return"
            case 0x10:
                self.prefix = "return-wide"
            case 0x11:
                self.prefix = "return-object"
            case _:
                raise OpCodeNotFoundError(self.opcode)

    def decode(self, fd):
        self.address = fd.tell() - 1
        self.decode_args(fd)

        if self.opcode == 0x0e:
            self.instruction_str = f"{self.prefix}"
        else:
            self.instruction_str = f"{self.prefix} v{self.vA}"

        self._build_operands()

    def execute(self, memory, registers):
        match self.opcode:
            case 0x0e: pass # 'return-void'
            case 0x10:
                memory.last_return = (registers[self.vA], registers[self.vA + 1])
            case _:
                memory.last_return = registers[self.vA]


class Const(InstructionBase):

    def fetch(self) -> None:
        self.prefix = "const"
        match self.opcode:
            case 0x12:
                self.fmt = '11n'
                self.suffix = "/4"
            case 0x13:
                self.fmt = '21s'
                self.suffix = "/16"
            case 0x14:
                self.fmt = '31i'
                self.prefix = "const"
            case 0x15:
                self.fmt = '21h'
                self.suffix = "/high16"
            case 0x16:
                self.fmt = '21s'
                self.prefix += "-wide"
                self.suffix = "/16"
            case 0x17:
                self.fmt = '31i'
                self.prefix += "-wide"
                self.suffix = "/32"
            case 0x18:
                self.fmt = '51l'
                self.prefix += "-wide"
            case 0x19:
                self.fmt = '21h'
                self.prefix += "-wide"
                self.suffix = "/high16"
            case 0x1a:
                self.fmt = '21c'
                self.prefix += "-string"
            case 0x1b:
                self.fmt = '31c'
                self.prefix += "-string"
                self.suffix = "/jumbo"
            case 0x1c:
                self.fmt = '21c'
            case _:
                raise OpCodeNotFoundError(self.opcode)

    def decode(self, fd):
        self.address = fd.tell() - 1
        self.decode_args(fd)

        match self.opcode:
            case 0x1a | 0x1b:
                string_val = self._safe_string(self.vB)
                self.instruction_str = f"{self.prefix}{self.suffix} v{self.vA}, \"{string_val}\""
            case 0x1c:
                type_name = self._safe_type(self.vB)
                self.instruction_str = f"{self.prefix}{self.suffix} v{self.vA}, {type_name}"
            case _:
                self.instruction_str = f"{self.prefix}{self.suffix} v{self.vA}, {self.vB:#x}"

        self._build_operands()

    def execute(self, memory, registers):
        match self.opcode:
            case 0x12 | 0x13 | 0x14 | 0x18:
                registers[self.vA] = self.vB
            case 0x15:
                registers[self.vA] = self.vB << 16
            case 0x16:
                registers[self.vA] = self.vB
            case 0x17:
                registers[self.vA] = self.vB
            case 0x18:
                registers[self.vA] = self.vB
            case 0x19:
                registers[self.vA] = self.vB << 48

            case 0x1a | 0x1b: # String lookup
                registers[self.vA] = memory.dex.string_ids[self.vB].value.raw_data

            case 0x1c: # Class lookup
                registers[self.vA] = self.vB

            case _:
                raise OpCodeNotFoundError(self.opcode)

        # If it's a 'wide' movement
        if self.opcode in [0x16, 0x17, 0x18, 0x19]:
            registers[self.vA + 1] = registers[self.vA] & 0xFFFFFFFF
            registers[self.vA] >>= 32


class Monitor(InstructionBase):

    def fetch(self) -> None:
        self.fmt = '11x'

        if self.opcode == 0x1d:
            self.prefix = "monitor-enter"
        elif self.opcode == 0x2d:
            self.prefix = "monitor-exit"

    def decode(self, fd):
        self.address = fd.tell() - 1
        self.decode_args(fd)
        self.instruction_str = f"{self.prefix} v{self.vA}"
        self._build_operands()


class CheckCast(InstructionBase):

    def fetch(self) -> None:
        self.fmt = '21c'
        self.prefix = "check-cast"

    def decode(self, fd):
        self.address = fd.tell() - 1
        self.decode_args(fd)
        type_name = self._safe_type(self.vB)
        self.instruction_str = f"{self.prefix} v{self.vA}, {type_name}"
        self._build_operands()


class InstanceOf(InstructionBase):

    def fetch(self) -> None:
        self.fmt = '22c'
        self.prefix = "instance-of"

    def decode(self, fd):
        self.address = fd.tell() - 1
        self.decode_args(fd)
        type_name = self._safe_type(self.vC)
        self.instruction_str = f"{self.prefix} v{self.vA} v{self.vB}, {type_name}"
        self._build_operands()

    # def execute(self, memory, registers):



class ArrLength(InstructionBase):

    def fetch(self) -> None:
        self.prefix = "array-length"
        self.fmt = '12x'

    def decode(self, fd):
        self.address = fd.tell() - 1
        self.decode_args(fd)
        self.instruction_str = f"{self.prefix} v{self.vA}, v{self.vB}"
        self._build_operands()

    def execute(self, memory, registers):
        try:
            registers[self.vA] = len(registers[self.vB])
        except TypeError as te:
            registers[self.vA] = 0


class NewInstance(InstructionBase):

    def fetch(self) -> None:
        self.prefix = "new-instance"
        self.fmt = '21c'

    def decode(self, fd):
        self.address = fd.tell() - 1
        self.decode_args(fd)
        type_name = self._safe_type(self.vB)
        self.instruction_str = f"{self.prefix} v{self.vA}, {type_name}"
        self._build_operands()

    def execute(self, memory, registers):
        if "String" in memory.dex.type_ids[self.vB].type_name:
            registers[self.vA] = ""
        else:
            registers[self.vA] = memory.dex.type_ids[self.vB].type_name


class Array(InstructionBase):

    def fetch(self) -> None:
        match self.opcode:
            case 0x23:
                self.fmt = '22c'
                self.prefix = "new-array"
            case 0x24:
                self.fmt = '35c'
                self.prefix = "filled-new-array"
            case 0x25:
                self.fmt = '3rc'
                self.prefix = "filled-new-array"
                self.suffix = "/range"
            case 0x26:
                self.fmt = '31t'
                self.prefix = "fill-array-data"
            case _:
                raise OpCodeNotFoundError(self.opcode)


    def decode(self, fd):
        self.address = fd.tell() - 1
        self.decode_args(fd)

        # TODO: Validate that these are properly parsing the instructions
        match self.opcode:
            case 0x23: # new-array
                type_name = self._safe_type(self.vC)
                self.instruction_str = f"{self.prefix} v{self.vA}, v{self.vB}, {type_name}"

            case 0x24: # filled-new-array
                type_name = self._safe_type(self.vB)
                all_regs = [self.vC, self.vD, self.vE, self.vF, self.vG]
                args = ", ".join(f"v{reg}" for reg in all_regs[:self.vA])
                self.instruction_str = f"{self.prefix} {{{args}}}, {type_name}"

            case 0x25: # filled-new-array/range
                type_name = self._safe_type(self.vB)
                self.instruction_str = f"{self.prefix}/{self.suffix} {{v{self.vC} .. v{self.vC + self.vA - 1 }}}, {type_name}"
            case 0x26: # fill-array-data
                self.instruction_str = f"{self.prefix} v{self.vA}, :array_UNRESOLVED"

        self._build_operands()


    def execute(self, memory, registers):
        match self.opcode:
            case 0x23:
                try: # Checking to make sure what's in vB is actually a num
                    registers[self.vA] = [0] * registers[self.vB]
                except TypeError as te:
                    log.error(f"TypeError: {te}")

            case 0x24:
                try:
                    registers[self.vA] = [""] * registers[self.vB]
                except TypeError as te:
                    log.error(f"TypeError: {te}")

            case 0x25:
                try:
                    num_items = self.vA + self.vC
                    registers[self.vA + num_items] = registers[self.vA:num_items - 1]
                    new_array = registers[self.vA:num_items - 1]
                except TypeError as te:
                    log.error(f"TypeError: {te}")

            case 0x26:
                payload_offset = self.address + (self.vB * 2)
                old_pos = memory.fd.tell()
                memory.fd.seek(payload_offset)

                # Skip array pseudo-instruction header (0x30 0x00) as we don't need/want it
                _, element_width, num_elements = struct.unpack('<HHI', memory.fd.read(8))

                for i in range(num_elements):
                    raw_item = memory.fd.read(element_width)

                    match element_width:
                        case 1: value,_ = struct.unpack('<b', raw_item) # byte
                        case 2: value,_ = struct.unpack('<h', raw_item) # short
                        case 4: value,_ = struct.unpack('<i', raw_item) # int
                        case 8: value,_ = struct.unpack('<q', raw_item) # long
                        case _: value   = int.from_bytes(raw_item, "little", signed=True)

                    try:
                        registers[self.vA][i] = value
                    except(IndexError, TypeError) as e:
                        log.error(f"fill-array-data failed at {i}: {e}")
                        break

                memory.fd.seek(old_pos)


class Throw(InstructionBase):

    def fetch(self) -> None:
        self.fmt = '11x'
        self.prefix = "throw"
        self.control_flow = ControlFlow.Terminate

    def decode(self, fd):
        self.address = fd.tell() - 1
        self.decode_args(fd)
        self.instruction_str = f"{self.prefix} v{self.vA}"
        self._build_operands()

    def execute(self, memory, registers):
        memory.last_exception = self.vA


class Goto(InstructionBase):

    def fetch(self) -> None:
        self.prefix = "goto"
        self.control_flow = ControlFlow.GoTo

        match self.opcode:
            case 0x28:
                self.fmt = '10t'
            case 0x29:
                self.fmt = '20t'
                self.suffix = "16"
            case 0x2a:
                self.fmt = '30t'
                self.suffix = "32"
            case _:
                raise OpCodeNotFoundError(self.opcode)

    def decode(self, fd):
        self.address = fd.tell() - 1
        self.decode_args(fd)
        self.instruction_str = f"{self.prefix} :goto_UNRESOLVED"
        self._build_operands()

    def execute(self, memory, registers):
        return self.vA

class Switch(InstructionBase):

    def __init__(self, opcode, dex):
        super().__init__(opcode, dex)
        self.switch_table = {}

    def fetch(self) -> None:
        self.fmt = '31t'
        self.prefix = "switch"

    def decode(self, fd):
        self.address = fd.tell() - 1
        self.decode_args(fd)
        self.instruction_str = f"switch v{self.vA}"

        # (try) to read Packed-Switch-Payload data
        old_fd = fd.tell() # Backup current cursor

        # vB == signed "branch" offset to table data
        payload_byte_offset = self.address + (self.vB * 2)
        fd.seek(payload_byte_offset) # navigates to the actual table data start
        fd.read(2) # Shift forward two spots (skipping the `ident` portion

        num_elements, = self._read(fd, '<H') # "size" = ushort <-- always present

        if self.opcode == 0x2b: # packed-switch
            element_base, = self._read(fd, '<i')
            for i in range(0, num_elements):
                offset, = self._read(fd, '<i')
                self.switch_table[element_base + i] = offset

        elif self.opcode == 0x2c: # sparse-switch
            keys = [self._read(fd, '<i')[0] for _ in range(num_elements)]
            # for i in range(0, num_elements): # keys
            #     self.switch_table[twos_complement(b2i(fd.read(4)), 4)] = 0

            targets = [self._read(fd, '<i')[0] for _ in range(num_elements)]
            # for key in self.switch_table.keys(): # target
            #     self.switch_table[key] = twos_complement(b2i(fd.read(4)), 4)
            self.switch_table = dict(zip(keys, targets))

        fd.seek(old_fd)
        self._build_operands()

    def execute(self, memory, registers):
        val = registers[self.vA]
        if val in self.switch_table:
            rel    = self.switch_table[val]
            target = self.codepoint + rel
            memory.last_exception = target
            return target

        # if no match, fall through
        memory.last_return = None
        return None

class Cmp(InstructionBase):

    def fetch(self) -> None:
        self.fmt = '23x'
        match self.opcode:
            case 0x2d:
                self.prefix = "cmpl-float"
            case 0x2e:
                self.prefix = "cmpg-float"
            case 0x2f:
                self.prefix = "cmpl-double"
            case 0x30:
                self.prefix = "cmpg-double"
            case 0x31:
                self.prefix = "cmp-long"
            case _:
                raise OpCodeNotFoundError(self.opcode)

    def decode(self, fd):
        self.address = fd.tell() - 1
        self.decode_args(fd)
        self.instruction_str = f"{self.prefix} v{self.vA}, v{self.vB}, v{self.vC}"
        self._build_operands()

    def execute(self, memory, registers):
        if self.opcode >= 0x2f:
            a = (registers[self.vB] << 32) + registers[self.vB + 1]
            b = (registers[self.vC] << 32) + registers[self.vC + 1]
        else:
            a = registers[self.vB]
            b = registers[self.vC]

        if not a or not b:
            match self.opcode:
                case 0x2d | 0x2f: c = -1
                case 0x2e | 0x30: c = 1
        else:
            if a > b: c = 1
            elif a < b: c = -1
            else: c = 0

        registers[self.vA] = c


class If(InstructionBase):

    def fetch(self) -> None:
        self.fmt = '22t'
        self.prefix = "if"
        self.control_flow = ControlFlow.Branch

        match self.opcode:
            case 0x32: self.prefix += "-eq"
            case 0x33: self.prefix += "-ne"
            case 0x34: self.prefix += "-lt"
            case 0x35: self.prefix += "-ge"
            case 0x36: self.prefix += "-gt"
            case 0x37: self.prefix += "-le"
            case _:
                raise OpCodeNotFoundError(self.opcode)

    def decode(self, fd):
        self.address = fd.tell() - 1
        self.decode_args(fd)
        self.instruction_str = f"{self.prefix} {self.vA}, {self.vB}, :cond_UNRESOLVED"
        self._build_operands()


    def execute(self, memory, registers):
        taken = False
        if registers[self.vA] and registers[self.vB]:
            match self.opcode:
                case 0x32: taken = registers[self.vA] == registers[self.vB]
                case 0x33: taken = registers[self.vA] != registers[self.vB]
                case 0x34: taken = registers[self.vA] < registers[self.vB]
                case 0x35: taken = registers[self.vA] >= registers[self.vB]
                case 0x36: taken = registers[self.vA] > registers[self.vB]
                case 0x37: taken = registers[self.vA] <= registers[self.vB]

        if taken:
            target = self.codepoint + sign_extend(self.vC, 16)
            memory.last_return = target
        else:
            memory.last_return = None

class IfZ(InstructionBase):

    def fetch(self) -> None:
        self.fmt = '21t'
        self.prefix = "if"
        self.control_flow = ControlFlow.Branch

        match self.opcode:
            case 0x38: self.prefix += "-eqz"
            case 0x39: self.prefix += "-nez"
            case 0x3a: self.prefix += "-ltz"
            case 0x3b: self.prefix += "-gez"
            case 0x3c: self.prefix += "-gtz"
            case 0x3d: self.prefix += "-lez"
            case _:
                raise OpCodeNotFoundError(self.opcode)

    def decode(self, fd):
        self.address = fd.tell() - 1
        self.decode_args(fd)
        self.instruction_str = f"{self.prefix} v{self.vA}, :cond_UNRESOLVED"
        self._build_operands()

    def execute(self, memory, registers):
        val = registers[self.vA]
        taken = False
        if registers[self.vA]:
            match self.opcode:
                case 0x38: taken = val == 0
                case 0x39: taken = val != 0
                case 0x3a: taken = val < 0
                case 0x3b: taken = val >= 0
                case 0x3c: taken = val > 0
                case 0x3d: tkane = val <= 0

        if taken:
            target = self.codepoint + sign_extend(self.vB, 16)
            memory.last_return = target
        else:
            memory.last_return = None


class ArrayOp(InstructionBase):

    def fetch(self) -> None:
        self.fmt = '23x'
        match self.opcode:
            case op if 0x44 <= op <= 0x4a:
                self.prefix = f"aget{MODIFIER_TYPE_LOOKUP[op - 0x44]}"
            case op if 0x4b <= op <= 0x51:
                self.prefix = f"aput{MODIFIER_TYPE_LOOKUP[op - 0x4b]}"
            case _:
                raise OpCodeNotFoundError(self.opcode)

    def decode(self, fd):
        self.address = fd.tell() - 1
        self.decode_args(fd)
        self.instruction_str = f"{self.prefix} v{self.vA}, v{self.vB}, v{self.vC}"
        self._build_operands()

    def execute(self, memory, registers):
        if 0x44 <= self.opcode <= 0x4a: # get
            try:
                registers[self.vA] = registers[self.vB][registers[self.vC]]
            except TypeError as te:
                log.error(f"TypeError encountered {te}: {registers[self.vB]}")

        elif 0x4b <= self.opcode <= 0x51: # put
            registers[self.vB][registers[self.vC]] = registers[self.vA]

class IGet(InstructionBase):

    def fetch(self) -> None:
        self.fmt = '22c'

        if 0x52 <= self.opcode <= 0x58:
            self.prefix = f"iget{MODIFIER_TYPE_LOOKUP[self.opcode - 0x52]}"
        else:
            raise OpCodeNotFoundError(self.opcode)

    def decode(self, fd):
        self.address = fd.tell() - 1
        self.decode_args(fd)
        field_ref = self._safe_field(self.vC)
        self.instruction_str = f"{self.prefix} v{self.vA}, v{self.vB}, {field_ref}"

        self._build_operands()

    def execute(self, memory, registers):
        registers[self.vA] = memory.instance_fields.get(self.vC, 0)

        if self.opcode == 0x53: # Wide
            registers[self.vA + 1] = registers[self.vA] & 0xFFFFFFFF
            registers[self.vA] = registers[self.vA] >> 32


class IPut(InstructionBase):

    def fetch(self) -> None:
        self.fmt = '22c'

        if 0x59 <= self.opcode <= 0x5Ff:
            self.prefix = f"iput{MODIFIER_TYPE_LOOKUP[self.opcode - 0x59]}"
        else:
            raise OpCodeNotFoundError(self.opcode)

    def decode(self, fd):
        self.address = fd.tell() - 1
        self.decode_args(fd)
        field_ref = self._safe_field(self.vC)
        self.instruction_str = f"{self.prefix} v{self.vA}, v{self.vB}, {field_ref}"

        self._build_operands()

    def execute(self, memory, registers):
        memory.instance_fields[self.vC] = registers[self.vA]

        if self.opcode == 0x5a:  # Wide
            memory.instance_fields[self.vC] <<= 32
            memory.instance_fields[self.vA] += registers[self.vA + 1]


class SGet(InstructionBase):

    def fetch(self) -> None:
        self.fmt = '21c'

        if 0x60 <= self.opcode <= 0x66:
            self.prefix = f"sget{MODIFIER_TYPE_LOOKUP[self.opcode - 0x60]}"
        else:
            raise OpCodeNotFoundError(self.opcode)

    def decode(self, fd):
        self.address = fd.tell() - 1
        self.decode_args(fd)
        field_ref = self._safe_field(self.vB)
        self.instruction_str = f"{self.prefix} v{self.vA}, {field_ref}"

        self._build_operands()

    def execute(self, memory, registers):
        registers[self.vA] = memory.static_fields.get(self.vB, None)

        if self.opcode == 0x61:  # Wide
            try:
                registers[self.vA + 1] = registers[self.vA] & 0xFFFFFFFF
                registers[self.vA] = registers[self.vA] >> 32

            except TypeError as te:
                log.error(f"TypeError encountered {te}: {registers[self.vA]}")
                registers[self.vA + 1] = 0
                registers[self.vA] = 0


class SPut(InstructionBase):

    def fetch(self) -> None:
        self.fmt = '21c'

        if 0x67 <= self.opcode <= 0x6d:
            self.prefix = f"sput{MODIFIER_TYPE_LOOKUP[self.opcode - 0x67]}"
        else:
            raise OpCodeNotFoundError(self.opcode)

    def decode(self, fd):
        self.address = fd.tell() - 1
        self.decode_args(fd)
        field_ref = self._safe_field(self.vB)
        self.instruction_str = f"{self.prefix} v{self.vA}, {field_ref}"

        self._build_operands()

    def execute(self, memory, registers):
        memory.static_fields[self.vB] = registers[self.vA]

        if self.opcode == 0x68:  # Wide
            try:
                memory.static_fields[self.vB] <<= 32
                memory.static_fields[self.vB] += registers[self.vA + 1]

            except TypeError as te:
                log.error(f"TypeError encountered {te}: {registers[self.vA]}. {registers[self.vA + 1]}")
                memory.static_fields[self.vB] = 0  # Reset field if junk is filling register


class InvokeKind(InstructionBase):

    def fetch(self) -> None:
        self.fmt = '35c'

        if 0x6e <= self.opcode <= 0x72:
            self.prefix = f"invoke{INVOKE_TYPE_LOOKUP[self.opcode - 0x6e]}"
        else:
            raise OpCodeNotFoundError(self.opcode)

    def decode(self, fd):
        self.address = fd.tell() - 1
        self.decode_args(fd)

        ref = self._safe_method(self.vB)
        all_regs = [self.vC, self.vD, self.vE, self.vF, self.vG]
        args = ", ".join(f"v{r}" for r in all_regs[:self.vA] if r is not None)
        self.instruction_str = f"{self.prefix} {{{args}}}, {ref}"

        self._build_operands()

    def execute(self, memory, registers):
        avail_params = [self.vC, self.vD, self.vE, self.vF, self.vG]
        method_ref = memory.dex.lookup_method(self.vB)
        params = avail_params[:self.vA] if self.vA > 0 else []
        return InstructionReturn(method_ref, True, params)

class InvokeKindRange(InstructionBase):

    def fetch(self) -> None:
        self.fmt = '3rc'

        if 0x74 <= self.opcode <= 0x78:
            self.prefix = f"invoke{INVOKE_TYPE_LOOKUP[self.opcode - 0x74]}"
        else:
            raise OpCodeNotFoundError(self.opcode)


    def decode(self, fd):
        self.address = fd.tell() - 1
        self.decode_args(fd)

        ref = self._safe_method(self.vB)
        self.instruction_str = f"{self.prefix} {{v{self.vC} .. v{self.vC + self.vA - 1}}}, {ref}"

        self._build_operands()

    def execute(self, memory, registers):
        params = [i for i in range(self.vC, self.vC + self.vA)]
        method_ref = memory.dex.lookup_method(self.vB)

        return InstructionReturn(method_ref, True, params)


class UnOp(InstructionBase):

    def fetch(self) -> None:
        self.fmt = '12x'
        match self.opcode:
            case 0x7b:
                self.prefix = "neg-int"
            case 0x7c:
                self.prefix = "not-int"
            case 0x7d:
                self.prefix = "neg-long"
            case 0x7e:
                self.prefix = "not-long"
            case 0x7f:
                self.prefix = "neg-float"
            case 0x80:
                self.prefix = "neg-double"
            case 0x81:
                self.prefix = "int-to-long"
            case 0x82:
                self.prefix = "int-to-float"
            case 0x83:
                self.prefix = "int-to-double"
            case 0x84:
                self.prefix = "long-to-int"
            case 0x85:
                self.prefix = "long-to-float"
            case 0x86:
                self.prefix = "long-to-double"
            case 0x87:
                self.prefix = "float-to-int"
            case 0x88:
                self.prefix = "float-to-long"
            case 0x89:
                self.prefix = "float-to-double"
            case 0x8a:
                self.prefix = "double-to-int"
            case 0x8b:
                self.prefix = "double-to-long"
            case 0x8c:
                self.prefix = "double-to-float"
            case 0x8d:
                self.prefix = "int-to-byte"
            case 0x8e:
                self.prefix = "int-to-char"
            case 0x8f:
                self.prefix = "int-to-short"
            case _:
                raise OpCodeNotFoundError(self.opcode)

    def decode(self, fd):
        self.address = fd.tell() - 1
        self.decode_args(fd)
        self.instruction_str = f"{self.prefix} v{self.vA}, v{self.vB}"
        self._build_operands()

    def execute(self, memory, registers):
        match self.opcode:
            case 0x7b | 0x7f: # neg-int | neg-float
                try:
                    registers[self.vA] = -registers[self.vB]
                except TypeError as te:
                    registers[self.vA] = 0
            case 0x7c | 0x7e: # not-int | not-long
                registers[self.vA] = ~registers[self.vB]
            case 0x7d | 0x80: # neg-long | neg-double
                registers[self.vA] = -registers[self.vB]
                registers[self.vA + 1] = -registers[self.vB + 1]
            case 0x82 | 0x86 | 0x87 | 0x8b: # int-to-float | long-to-double | float-to-int | double-to-long
                pass # datatype is (mostly) interchangeable and not type change is needed
            case 0x81 | 0x83 | 0x88 | 0x89: # int-to-long | int-to-double | float-to-long | float-to-double
                registers[self.vA] = registers[self.vB]
                registers[self.vA + 1] = 0x0 # Just set it to 0
            case 0x84 | 0x85 | 0x8a | 0x8c: # long-to-int | long-to-float | double-to-int | double-to-float
                val1 = registers[self.vB]
                val2 = registers[self.vB + 1]

                long_value = (val1 << 32) or (val2 & 0xFFFFFFFF)
                registers[self.vA] = long_value

            case 0x8d | 0x8e: # int-to-byte | int-to-char
                val = registers[self.vB] & 0xFF
                registers[self.vA] = (val - 0xFF - 1) if val > 0x7F else val
            case 0x8f:
                val = registers[self.vB] & 0xFFFF
                registers[self.vA] = (val - 0xFFFF - 1) if val > 0x7FFF else val


### Binary Instruction Operands
# find out the operator type and the operand type
# ------------OPERANDS-------------
# 0 - int
# 1 - long
# 2 - float
# 3 - double
# ------------OPERATORS------------
# 0 - add
# 1 - sub
# 2 - mul
# 3 - div
# 4 - rem
# 5 - and
# 6 - or
# 7 - xor
# 8 - shl
# 9 - shr
# a - ushr
class BinOp(InstructionBase):

    def fetch(self) -> None:
        self.fmt = '23x'

        if 0x90 <= self.opcode <= 0xa5:
            self.operand_type  = (self.opcode - 0x90) // 11
            self.operator_type = (self.opcode - 0x90) % 11
        elif 0xa6 <= self.opcode <= 0xaf:
            self.operand_type = (self.opcode - 0xa6) // 5 + 2
            self.operator_type = (self.opcode - 0xa6) % 5
        else:
            raise OpCodeNotFoundError(self.opcode)

        self.prefix = BIN_OPERATOR_LOOKUP[self.operator_type] + "-" + BIN_OPERAND_LOOKUP[self.operand_type]

    def decode(self, fd):
        self.address = fd.tell() - 1
        self.decode_args(fd)
        self.instruction_str = f"{self.prefix} v{self.vA}, v{self.vB}, v{self.vC}"
        self._build_operands()

    def execute(self, memory, registers):
        b = None
        c = None

        match self.operand_type:
            case 0x0: # int
                b = registers[self.vB]
                c = registers[self.vC]

            case 0x1: # long
                b = (registers[self.vB] << 32) or registers[self.vB + 1]

                # "two and one" register value retrieval edge case
                if self.operator_type in [0x8, 0x9, 0xa]: # shl, shr, ushr
                    c = registers[self.vC]
                else:
                    c = (registers[self.vB] << 32) or registers[self.vB + 1]

            case 0x2 | 0x3: # float or double
                b = (registers[self.vB] << 32) or registers[self.vB + 1]
                c = (registers[self.vB] << 32) or registers[self.vB + 1]


        try:
            a = reg_ops_helper(self.operator_type, self.operand_type, b, c)
        except ZeroDivisionError as zde:
            a = 0

        match self.operand_type:
            case 0x0 | 0x4: # int or float
                registers[self.vA] = a
            case 0x1 | 0x3: # long or double
                registers[self.vA] = a >> 32
                registers[self.vA + 1] = a & 0xFFFFFFFF


class BinOp2Addr(InstructionBase):

    def fetch(self) -> None:
        self.fmt = '12x'
        self.suffix = "/2addr"

        if 0xb0 <= self.opcode <= 0xc5:
            self.operand_type  = (self.opcode - 0xb0) // 11
            self.operator_type = (self.opcode - 0xb0) % 11
        elif 0xc6 <= self.opcode <= 0xcf:
            self.operand_type = (self.opcode - 0xc6) // 5 + 2
            self.operator_type = (self.opcode - 0xc6) % 5
        else:
            raise OpCodeNotFoundError(self.opcode)

        self.prefix = BIN_OPERATOR_LOOKUP[self.operator_type] + "-" + BIN_OPERAND_LOOKUP[self.operand_type]

    def decode(self, fd):
        self.address = fd.tell() - 1
        self.decode_args(fd)
        self.instruction_str = f"{self.prefix}{self.suffix} v{self.vA}, v{self.vB}"
        self._build_operands()

    def print_instruction(self):
        log.debug("%s-%s/2addr v%s v%s" % (self.prefix, self.suffix, self.vA, self.vB))

    def execute(self, memory, registers):
        a = None
        b = None

        match self.operand_type:
            case 0x0: # int
                a = registers[self.vA]
                b = registers[self.vB]

            case 0x1: # long
                b = (registers[self.vA] << 32) or registers[self.vA + 1]

                # "two and one" register value retrieval edge case
                if self.operator_type in [0x8, 0x9, 0xa]: # shl, shr, ushr
                    c = registers[self.vB]
                else:
                    c = (registers[self.vA] << 32) or registers[self.vA + 1]

            case 0x2 | 0x3: # float or double
                b = (registers[self.vA] << 32) or registers[self.vA + 1]
                c = (registers[self.vA] << 32) or registers[self.vA + 1]


        try:
            a = reg_ops_helper(self.operator_type, self.operand_type, a, b)
        except ZeroDivisionError as zde:
            a = 0

        match self.operand_type:
            case 0x0 | 0x4: # int or float
                registers[self.vA] = a
            case 0x1 | 0x3: # long or double
                registers[self.vA] = a >> 32
                registers[self.vA + 1] = a & 0xFFFFFFFF


class BinOpLit(InstructionBase):

    def fetch(self) -> None:

        if 0xd0 <= self.opcode <= 0xd7:
            self.fmt = '22s'
            self.operator_type = self.opcode - 0xd0
            self.suffix = "/lit16"

        elif 0xd8 <= self.opcode <= 0xe2:
            self.fmt = '22b'
            self.operator_type = self.opcode - 0xd8
            self.suffix = "/lit8"

        else:
            raise OpCodeNotFoundError(self.opcode)

        self.prefix = BIN_OPERATOR_LOOKUP[self.operator_type] + "-int"

    def decode(self, fd):
        self.address = fd.tell() - 1
        self.decode_args(fd)
        self.instruction_str = f"{self.prefix}{self.suffix} v{self.vA}, v{self.vB}, {self.vC:#x}"
        self._build_operands()

    def execute(self, memory, registers):
        b = registers[self.vB] # passed in value
        c = self.vC # literal value

        if self.operator_type != 0x1:
            a = reg_ops_helper(self.operator_type, self.operand_type, b, c)
        else: # In the case of 'rsub', switch the two values around
            a = reg_ops_helper(self.operator_type, self.operand_type, c, b)

        registers[self.vA] = a


class InvokePolymorphic(InstructionBase):

    def fetch(self) -> None:
        self.prefix = "invoke-polymorphic"

        match self.opcode:
            case 0xfa:
                self.fmt = '45rcc'
            case 0xfb:
                self.fmt = '4rcc'
                self.suffix = "/range"
            case _:
                raise OpCodeNotFoundError(self.opcode)

    def decode(self, fd):
        self.address = fd.tell() - 1
        self.decode_args(fd)
        method_ref = self.dex.dex.methods[self.vB]
        ref = f"{method_ref.class_name}->{method_ref.method_name}{method_ref.proto_desc}"
        if self.opcode == 0xfa: # invoke-polymorphic
            all_regs = [self.vC, self.vD, self.vE, self.vF, self.vG]
            args = ", ".join(f"v{r}" for r in all_regs[:self.vA] if r is not None)
            self.instruction_str = f"{self.prefix} {{{args}}}, {ref}, proto@{self.vH}"
        else: # invoke-polymorphic/range
            self.instruction_str = f"{self.prefix}{self.suffix} {{v{self.vC} .. v{self.vC + self.vA - 1}, {ref}, proto@{self.vH}"

        self._build_operands()

    def execute(self, memory, registers):
        method_ref = memory.dex.lookup_method(self.vB)
        proto_ref = memory.dex.proto_ids[self.vH].shorty_desc

        if self.opcode == 0xfa:  # invoke-polymorphic
            avail_params = [self.vC, self.vD, self.vE, self.vF, self.vG]
            params = [registers[r] for r in avail_params[:self.vA] if r is not None]
        else:  # invoke-polymorphic/range
            params = [registers[i] for i in range(self.vC, self.vC + self.vA)]

        # The receiver (p0) is the MethodHandle object itself
        method_handle = registers[params[0]] if params else None

        if method_handle is None:
            log.error("invoke-polymorphic: null MethodHandle")
            memory.last_return = None
            return InstructionReturn(None, False, [])

        return InstructionReturn(method_ref, True, params)

class InvokeCustom(InstructionBase):

    def fetch(self) -> None:
        self.prefix = "invoke-custom"

        match self.opcode:
            case 0xfc:
                self.fmt = '35c'
            case 0xfd:
                self.fmt = '35rc'
                self.suffix = "/range"
            case _:
                raise OpCodeNotFoundError(self.opcode)

    def decode(self, fd):
        self.address = fd.tell() - 1
        self.decode_args(fd)

        if self.opcode == 0xfc:
            all_regs = [self.vC, self.vD, self.vE, self.vF, self.vG]
            args = ", ".join(f"v{r}" for r in all_regs[:self.vA] if r is not None)
            self.instruction_str = f"{self.prefix} {{{args}}}, call_site@{self.vB}"
        else:
            self.instruction_str = f"{self.prefix}{self.suffix} {{v{self.vC} .. v{self.vC + self.vA - 1}}}, call_site@{self.vB}"

        self._build_operands()


    def execute(self, memory, registers):
        # Resolve the call site from the DEX call_site_ids table

        if self.opcode == 0xfc:
            avail_regs = [self.vC, self.vD, self.vE, self.vF, self.vG]
            runtime_args = [registers[r] for r in avail_regs[:self.vA] if r is not None]
        else:
            runtime_args = [registers[i] for i in range(self.vC, self.vC + self.vA)]

        resolver = CallSiteResolver(memory)
        result   = resolver.resolve(self.vB, runtime_args)

        memory.last_return = result
        return InstructionReturn(result, True, runtime_args)


class ConstMethod(InstructionBase):

    def fetch(self) -> None:
        self.prefix = "const-method"
        self.fmt = '21c'
        match self.opcode:
            case 0xfe:
                self.prefix += "-handle"
            case 0xff:
                self.prefix += "-type"
            case _:
                raise OpCodeNotFoundError(self.opcode)


    def decode(self, fd):
        self.address = fd.tell() - 1
        self.decode_args(fd)
        self.instruction_str = f"{self.prefix} v{self.vA}, {self.vB}"
        self._build_operands()

    def execute(self, memory, registers):
        if self.opcode == 0xfe:  # const-method-handle
            try:
                method_handle = memory.dex.dex.method_handles[self.vB]
                registers[self.vA] = method_handle
            except (IndexError, AttributeError) as e:
                log.error(f"const-method-handle: failed to resolve handle {self.vB}: {e}")
                registers[self.vA] = None

        elif self.opcode == 0xff:  # const-method-type
            try:
                proto = memory.dex.dex.proto_ids[self.vB]
                registers[self.vA] = proto
            except (IndexError, AttributeError) as e:
                log.error(f"const-method-type: failed to resolve proto {self.vB}: {e}")
                registers[self.vA] = None