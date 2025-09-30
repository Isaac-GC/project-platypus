import logging
from typing import BinaryIO

from dex.helpers import b2i, nibble_at, twos_complement
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

class ControlFlow:
    Terminate = 0x0
    GoTo = 0x1
    Branch = 0x2
    FallThrough = 0x3


class OpCodeNotFoundError(Exception):
    def __init__(self, opcode):
        super().__init__(f"{hex(opcode)} not defined, try another decoder")

class InstructionReturn:
    def __init__(self, ret, is_external_call, parameters):
        self.ret = ret
        self.is_external_call = is_external_call
        self.parameters = parameters

class InstructionBase:

    def __init__(self, opcode):
        self.address: int = 0
        self.fmt: int     = 0x0
        self.opcode:int   = opcode

        self.prefix: str = "nop"
        self.suffix: str = ""

        self.control_flow = ControlFlow.FallThrough

        # used by some instructions
        self.operator_type = 0
        self.operand_type = 0

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
        return self.decode_args_by_format(self.fmt, fd)

    def decode_args_by_format(self, fmt: int, fd: BinaryIO):
        decoded_args:  list = []
        returned_args: list = []

        tail = fmt & 0xF

        fmt >>= 4

        arg_length = 1 # Arg length in nibbles (4 bits)
        while fmt:
            if tail != fmt & 0xF:
                decoded_args.append({
                    'len': arg_length,
                    'signed': tail >= 0xA
                })
                arg_length = 1
                tail = fmt & 0xF

            else:
                arg_length += 1

            fmt >>= 4

        decoded_args.append({
            'len': arg_length,
            'signed': tail >= 0xA
        })

        while len(decoded_args) > 0:
            decoded_arg = decoded_args.pop()

            if decoded_arg['len'] == 1:
                byte = b2i(fd.read(1))
                nibble_0: int = nibble_at(byte, 0)
                nibble_1: int = nibble_at(byte, 1)

                if decoded_arg['signed']:
                    nibble_0 = twos_complement(nibble_0, 0.5)

                decoded_arg = decoded_args.pop()

                if decoded_arg['signed']:
                    nibble_1 = twos_complement(nibble_1, 0.5)

                returned_args += [nibble_0, nibble_1]

            else:
                bytez = b2i(fd.read(decoded_arg['len'] // 2))
                if decoded_arg['signed']:
                    nibble_1 = twos_complement(bytez, decoded_arg['len'] // 2)

                return returned_args.append(bytez)

            if len(returned_args) > 1:
                return tuple(returned_args)
            else:
                return returned_args[0]


    def execute(self, memory, registers):
        return InstructionReturn(1, False, [])


class Nop(InstructionBase):

    def fetch(self) -> None:
        self.fmt = 0x11




class Move(InstructionBase):

    def fetch(self) -> None:
        obj_type = ["", "-wide", "-object"]
        self.prefix = f"move{obj_type[self.opcode // 3]}"

        match self.opcode:
            case 0x01 | 0x04 | 0x07:
                self.fmt = 0x12
            case 0x02 | 0x05 | 0x08:
                self.fmt = 0x112222
                self.suffix = "from16"
            case 0x03 | 0x06 | 0x09:
                self.fmt = 0x11112222
                self.suffix = "16"
            case _:
                raise OpCodeNotFoundError(self.opcode)

    def decode(self, fd) -> None:
        self.address = fd.tell() - 1

        # align bytes
        if self.opcode in [0x03, 0x06, 0x09]:
            fd.read(1)
        (self.vA, self.vB) = self.decode_args(fd)

    def execute(self, memory, registers):
        if self.opcode not in [0x04, 0x05, 0x06]: # wide instructions
            registers[self.vA] = registers[self.vB]
        else: # Do 'wide' move
            registers[self.vA] = registers[self.vB]
            registers[self.vA + 1] = registers[self.vB + 1]

        memory.last_return = 1


class MoveResult(InstructionBase):

    def fetch(self) -> None:
        self.fmt = 0x11

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
        self.vA = self.decode_args(fd)

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

        memory.last_return = 1

class Return(InstructionBase):

    def fetch(self) -> None:
        self.fmt = 0x11
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
        self.vA = self.decode_args(fd)

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
                self.fmt = 0x1A
                self.suffix = "4"
            case 0x13:
                self.fmt = 0x11AAAA
                self.suffix = "16"
            case 0x14:
                self.fmt = 0x11AAAAAAAA
                self.prefix = "const"
            case 0x15:
                self.fmt = 0x11AAAA
                self.suffix = "high16"
            case 0x16:
                self.fmt = 0x11AAAA
                self.prefix += "-wide"
                self.suffix = "16"
            case 0x17:
                self.fmt = 0x11AAAAAAAA
                self.prefix += "-wide"
                self.suffix = "32"
            case 0x18:
                self.fmt = 0x11AAAAAAAAAAAAAAAA
                self.prefix += "-wide"
            case 0x19:
                self.fmt = 0x11AAAA
                self.prefix += "-wide"
                self.suffix = "high16"
            case 0x1a:
                self.fmt = 0x112222
                self.prefix += "-string"
            case 0x1b:
                self.fmt = 0x1122222222
                self.prefix += "-string"
                self.suffix = "jumbo"
            case 0x1c:
                self.fmt = 0x112222
            case _:
                raise OpCodeNotFoundError(self.opcode)

    def decode(self, fd):
        self.address = fd.tell() - 1
        (self.vA, self.vB) = self.decode_args(fd)

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
        self.fmt = 0x11
        self.prefix = "monitor"

    def decode(self, fd):
        self.address = fd.tell() - 1
        self.vA = self.decode_args(fd)


class CheckCast(InstructionBase):

    def fetch(self) -> None:
        self.fmt = 0x112222
        self.prefix = "check-cast"

    def decode(self, fd):
        self.address = fd.tell() - 1
        (self.vA, self.vB) = self.decode_args(fd)


class InstanceOf(InstructionBase):

    def fetch(self) -> None:
        self.fmt = 0x123333
        self.prefix = "instanceof"

    def decode(self, fd):
        self.address = fd.tell() - 1
        (self.vA, self.vB, self.vC) = self.decode_args(fd)

    # def execute(self, memory, registers):



class ArrLength(InstructionBase):

    def fetch(self) -> None:
        self.prefix = "array-length"
        match self.opcode:
            case 0x21:
                self.fmt = 0x12
            case _:
                raise OpCodeNotFoundError(self.opcode)

    def decode(self, fd):
        self.address = fd.tell() - 1
        (self.vA, self.vB) = self.decode_args(fd)

    def execute(self, memory, registers):
        try:
            registers[self.vA] = len(registers[self.vB])
        except TypeError as te:
            registers[self.vA] = 0


class NewInstance(InstructionBase):

    def fetch(self) -> None:
        self.prefix = "new-instance"
        match self.opcode:
            case 0x22:
                self.fmt = 0x112222
            case _:
                raise OpCodeNotFoundError(self.opcode)

    def decode(self, fd):
        self.address = fd.tell() - 1
        (self.vA, self.vB) = self.decode_args(fd)

    def execute(self, memory, registers):
        if "String" in memory.dex.type_ids[self.vB].type_name:
            registers[self.vA] = ""
        else:
            registers[self.vA] = memory.dex.type_ids[self.vB].type_name


class Array(InstructionBase):

    def fetch(self) -> None:
        match self.opcode:
            case 0x23:
                self.fmt = 0x123333
                self.prefix = "new-array"
            case 0x24:
                self.fmt = 0x1233334567
                self.prefix = "filled-new-array"
            case 0x25:
                self.fmt = 0x1122223333
                self.prefix = "filled-new-array"
                self.suffix = "range"
            case 0x26:
                self.fmt = 0x11AAAAAAAA
                self.prefix = "fill-array-data"
            case _:
                raise OpCodeNotFoundError(self.opcode)


    def decode(self, fd):
        self.address = fd.tell() - 1

        match self.opcode:
            case 0x23:
                (self.vA, self.vB, self.vC) = self.decode_args(fd)
            case 0x24:
                (self.vA, self.vG, self.vB, self.vF, self.vE, self.vD, self.vC) = self.decode_args(fd)
            case 0x25:
                (self.vA, self.vB, self.vC) = self.decode_args(fd)
            case 0x26:
                (self.vA, self.vB) = self.decode_args(fd)

    def execute(self, memory, registers):
        match self.opcode:
            case 0x23:
                new_array = []
                try: # Checking to make sure whats in vB is actually a num
                    new_array = [0 for i in range(registers[self.vB])]
                except TypeError as te:
                    log.error(f"TypeError: {te}")

                registers[self.vA] = new_array

            case 0x24:
                new_array = []
                given_type = memory.dex.type_ids[self.vB].type_name

                try:  # Checking to make sure whats in vB is actually a num
                    if "String" in given_type:
                        new_array = ["" for i in range(registers[self.vB])]

                    else: # TODO: Probably should expand this to cover additional types
                        new_array = ["" for i in range(registers[self.vB])]

                except TypeError as te:
                    log.error(f"TypeError: {te}")

                registers[self.vA] = new_array

            case 0x25:
                new_array = []
                num_items = 0
                try:  # Checking to make sure whats in vB is actually a num
                    num_items = self.vA + self.vC
                    new_array = registers[self.vA:num_items - 1]

                except TypeError as te:
                    log.error(f"TypeError: {te}")

                registers[self.vA + num_items] = new_array

            case 0x26:
                # Skip array pseudo-instruction header (0x30 0x00) as we don't need/want it
                memory.fd.seek(self.address + (self.vB * 2) + 2)

                (element_width, num_elements) = self.decode_args_by_format(0x111122222222, memory.fd)
                for i in range(num_elements):
                    registers[self.vA][i] = b2i(memory.fd.read(element_width))

                # Restore PC, skipping over the read instruction data
                memory.fd.seek(self.address + 6)


class Throw(InstructionBase):

    def fetch(self) -> None:
        self.fmt = 0x11
        self.prefix = "throw"
        self.control_flow = ControlFlow.Terminate

    def decode(self, fd):
        self.address = fd.tell() - 1
        self.vA = self.decode_args(fd)

    def execute(self, memory, registers):
        memory.last_exception = self.vA


class Goto(InstructionBase):

    def fetch(self) -> None:
        self.prefix = "goto"
        self.control_flow = ControlFlow.GoTo

        match self.opcode:
            case 0x28:
                self.fmt = 0xAA
            case 0x29:
                self.fmt = 0xAAAA
                self.suffix = "16"
            case 0x2a:
                self.fmt = 0xAAAAAAAA
                self.suffix = "32"
            case _:
                raise OpCodeNotFoundError(self.opcode)

    def decode(self, fd):
        self.address = fd.tell() - 1

        # Needed to align to /16 and /32 constants
        if self.opcode in [0x29, 0x2a]:
            fd.read(1)
        self.vA = self.decode_args(fd)

    def execute(self, memory, registers):
        # Lookup the next instruction address
        return self.address + (self.vA * 2)


class Switch(InstructionBase):

    def __init__(self, opcode):
        super().__init__(opcode)
        self.switch_table = {}

    def fetch(self) -> None:
        self.fmt = 0x11AAAAAAAA
        self.prefix = "switch"

    def decode(self, fd):
        self.address = fd.tell() - 1
        (self.vA, self.vB) = self.decode_args(fd)

        # Read packed switch data
        old_fd = fd.tell()

        fd.seek(old_fd + (self.vB * 2) - 6)
        fd.read(2) # Shift forward two spots

        num_elements = b2i(fd.read(2))

        if self.opcode == 0x2b: # packed-switch
            element_base = twos_complement(b2i(fd.read(4)), 4)
            for i in range(0, num_elements):
                self.switch_table[element_base + i] = twos_complement(b2i(fd.read(4)), 4)

        elif self.opcode == 0x2c: # sparse-switch
            for i in range(0, num_elements):
                self.switch_table[twos_complement(b2i(fd.read(4)), 4)] = 0
            for key in self.switch_table.keys():
                self.switch_table[key] = twos_complement(b2i(fd.read(4)), 4)

        fd.seek(old_fd)

    def execute(self, memory, registers):
        found_switch_branch = False
        ret = 1
        for value, offset in self.switch_table.items():
            if registers[self.vA] == value:
                ret = self.address + offset + 2
                found_switch_branch = True

        if found_switch_branch:
            memory.last_return = ret


class Cmp(InstructionBase):

    def fetch(self) -> None:
        self.fmt = 0x112233
        self.prefix = "cmp"

    def decode(self, fd):
        self.address = fd.tell() - 1
        (self.vA, self.vB, self.vC) = self.decode_args(fd)

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
        self.fmt = 0x12AAAA
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
        (self.vA, self.vB, self.vC) = self.decode_args(fd)

    def execute(self, memory, registers):
        ret = 1

        if registers[self.vA] and registers[self.vB]:
            match self.opcode:
                case 0x32:
                    if registers[self.vA] == registers[self.vB]:
                        ret = self.address + self.vC * 2

                case 0x33:
                    if registers[self.vA] != registers[self.vB]:
                        ret = self.address + self.vC * 2

                case 0x34:
                    if registers[self.vA] < registers[self.vB]:
                        ret = self.address + self.vC * 2

                case 0x35:
                    if registers[self.vA] >= registers[self.vB]:
                        ret = self.address + self.vC * 2

                case 0x36:
                    if registers[self.vA] > registers[self.vB]:
                        ret = self.address + self.vC * 2

                case 0x37:
                    if registers[self.vA] <= registers[self.vB]:
                        ret = self.address + self.vC * 2

        memory.last_return = ret

class Ifz(InstructionBase):

    def fetch(self) -> None:
        self.fmt = 0x11AAAA
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
        (self.vA, self.vB) = self.decode_args(fd)

    def execute(self, memory, registers):
        ret = 1
        if registers[self.vA]:
            match self.opcode:
                case 0x38:
                    if registers[self.vA] == 0:
                        ret = self.address + self.vB * 2
                case 0x39:
                    if registers[self.vA] != 0:
                        ret = self.address + self.vB * 2
                case 0x3a:
                    if registers[self.vA] < 0:
                        ret = self.address + self.vB * 2
                case 0x3b:
                    if registers[self.vA] >= 0:
                        ret = self.address + self.vB * 2
                case 0x3c:
                    if registers[self.vA] > 0:
                        ret = self.address + self.vB * 2
                case 0x3d:
                    if registers[self.vA] <= 0:
                        ret = self.address + self.vB * 2

            memory.last_return = ret


class ArrayOp(InstructionBase):

    def fetch(self) -> None:
        self.fmt = 0x112233
        match self.opcode:
            case op if 0x44 <= op <= 0x4a:
                self.prefix = f"aget{MODIFIER_TYPE_LOOKUP[op - 0x44]}"
            case op if 0x4b <= op <= 0x51:
                self.prefix = f"aget{MODIFIER_TYPE_LOOKUP[op - 0x4b]}"
            case _:
                raise OpCodeNotFoundError(self.opcode)

    def decode(self, fd):
        self.address = fd.tell() - 1
        (self.vA, self.vB, self.vC) = self.decode_args(fd)

    def execute(self, memory, registers):
        if 0x44 <= self.opcode <= 0x4a:
            try:
                registers[self.vA] = registers[self.vB][registers[self.vC]]
            except TypeError as te:
                log.error(f"TypeError encountered {te}: {registers[self.vB]}")

        elif 0x4b <= self.opcode <= 0x51:
            registers[self.vB][registers[self.vC]] = registers[self.vA]


class IGet(InstructionBase):

    def fetch(self) -> None:
        self.fmt = 0x123333

        if 0x52 <= self.opcode <= 0x58:
            self.prefix = f"iget{MODIFIER_TYPE_LOOKUP[self.opcode - 0x52]}"
        else:
            raise OpCodeNotFoundError(self.opcode)

    def decode(self, fd):
        self.address = fd.tell() - 1
        (self.vA, self.vB, self.vC) = self.decode_args(fd)

    def execute(self, memory, registers):
        if self.vC == 4418: pass # Handle this

        registers[self.vA] = memory.instance_fields.get(self.vC, 0)

        if self.opcode == 0x53: # Wide
            registers[self.vA + 1] = registers[self.vA] & 0xFFFFFFFF
            registers[self.vA] = registers[self.vA] >> 32


class IPut(InstructionBase):

    def fetch(self) -> None:
        self.fmt = 0x123333

        if 0x59 <= self.opcode <= 0x5Ff:
            self.prefix = f"iput{MODIFIER_TYPE_LOOKUP[self.opcode - 0x59]}"
        else:
            raise OpCodeNotFoundError(self.opcode)

    def decode(self, fd):
        self.address = fd.tell() - 1
        (self.vA, self.vB, self.vC) = self.decode_args(fd)

    def execute(self, memory, registers):
        memory.instance_fields[self.vC] = registers[self.vA]

        if self.opcode == 0x5a:  # Wide
            memory.instance_fields[self.vC] <<= 32
            memory.instance_fields[self.vA] += registers[self.vA + 1]


class SGet(InstructionBase):

    def fetch(self) -> None:
        self.fmt = 0x123333

        if 0x60 <= self.opcode <= 0x66:
            self.prefix = f"sget{MODIFIER_TYPE_LOOKUP[self.opcode - 0x66]}"
        else:
            raise OpCodeNotFoundError(self.opcode)

    def decode(self, fd):
        self.address = fd.tell() - 1
        (self.vA, self.vB) = self.decode_args(fd)

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
        self.fmt = 0x112222

        if 0x67 <= self.opcode <= 0x6d:
            self.prefix = f"sput{MODIFIER_TYPE_LOOKUP[self.opcode - 0x67]}"
        else:
            raise OpCodeNotFoundError(self.opcode)

    def decode(self, fd):
        self.address = fd.tell() - 1
        (self.vA, self.vB) = self.decode_args(fd)

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
        self.fmt = 0x1233334567

        if 0x6e <= self.opcode <= 0x72:
            self.prefix = f"invoke{INVOKE_TYPE_LOOKUP[self.opcode - 0x6e]}"
        else:
            raise OpCodeNotFoundError(self.opcode)

    def decode(self, fd):
        self.address = fd.tell() - 1
        (self.vA, self.vG, self.vB, self.vF, self.vE, self.vD, self.vC) = self.decode_args(fd)

    def execute(self, memory, registers):
        avail_params = [self.vC, self.vD, self.vE, self.vF, self.vG]
        method_ref = memory.dex.lookup_method(self.vB)
        params = []
        if self.vA > 0:
            params = avail_params[0:self.vA]

        memory.method_instr_values = {
            'method_ref': method_ref,
            'is_external_call': True,
            'params': params
        }

class InvokeKindRange(InstructionBase):

    def fetch(self) -> None:
        self.fmt = 0x1122223333

        if 0x74 <= self.opcode <= 0x78:
            self.prefix = f"invoke{INVOKE_TYPE_LOOKUP[self.opcode - 0x74]}"
        else:
            raise OpCodeNotFoundError(self.opcode)


    def decode(self, fd):
        self.address = fd.tell() - 1
        (self.vA, self.vB, self.vC) = self.decode_args(fd)

    def execute(self, memory, registers):
        params = [i for i in range(self.vC, self.vC + self.vA)]
        method_ref = memory.dex.lookup_method(self.vB)

        memory.method_instr_values = {
            'method_ref': method_ref,
            'is_external_call': True,
            'params': params
        }


class UnOp(InstructionBase):

    def fetch(self) -> None:
        self.fmt = 0x12
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
        (self.vA, self.vB) = self.decode_args(fd)

    def execute(self, memory, registers):
        match self.opcode:
            case 0x7b | 0x7f: # neg-int | neg-float
                try:
                    registers[self.vA] = -registers[self.vB]
                except TypeError as te:
                    registers[self.vA] = 0
            case 0x7c | 0x7e: # not-int | not-long
                ~registers[self.vA] = ~registers[self.vB]
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
        self.fmt = 0x112233

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
        (self.vA, self.vB, self.vC) = self.decode_args(fd)

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
        self.fmt = 0x12
        self.suffix = "2addr"

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
        (self.vA, self.vB) = self.decode_args(fd)

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


class BinOpLit(InstructionBase):

    def fetch(self) -> None:

        if 0xd0 <= self.opcode <= 0xd7:
            self.fmt = 0x12AAAA
            self.operator_type = self.opcode - 0xd0
            self.suffix = "lit16"

        elif 0xd8 <= self.opcode <= 0xe2:
            self.fmt = 0x1122AA
            self.operator_type = self.opcode - 0xd8
            self.suffix = "lit8"

        else:
            raise OpCodeNotFoundError(self.opcode)

        self.prefix = BIN_OPERATOR_LOOKUP[self.operator_type] + "-int"

    def decode(self, fd):
        self.address = fd.tell() - 1
        (self.vA, self.vB, self.vC) = self.decode_args(fd)

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
                self.fmt = 0x12333345678888
            case 0xfb:
                self.fmt = 0x11222233334444
                self.suffix = "range"
            case _:
                raise OpCodeNotFoundError(self.opcode)

    def decode(self, fd):
        self.address = fd.tell() - 1

        if self.opcode == 0xfa: # invoke-polymorphic
            (self.vA, self.vG, self.vB, self.vF, self.vE, self.vD, self.vC, self.vH) = self.decode_args(fd)
        else: # invoke-polymorphic/range
            (self.vA, self.vB, self.vC, self.vH) = self.decode_args(fd)

    def execute(self, memory, registers):
        method_ref = memory.dex.lookup_method(self.vB)
        proto_ref = memory.dex.proto_ids[self.vH].shorty_desc

        # if self.opcode == 0xfa:
        params = [i for i in range(self.vC, self.vC + self.vA)]
        memory.method_instr_values = {
            'method_ref': method_ref,
            'proto_ref': proto_ref,
            'is_external_call': True,
            'params': params
        }

class InvokeCustom(InstructionBase):

    def fetch(self) -> None:
        self.prefix = "invoke-custom"

        match self.opcode:
            case 0xfc:
                self.fmt = 0x1233334567
            case 0xfd:
                self.fmt = 0x1122223333
                self.suffix = "range"
            case _:
                raise OpCodeNotFoundError(self.opcode)

    def decode(self, fd):
        self.address = fd.tell() - 1

        if self.opcode == 0xfc:
            (self.vA, self.vG, self.vB, self.vF, self.vE, self.vD, self.vC) = self.decode_args(fd)
        else:
            (self.vA, self.vB, self.vC) = self.decode_args(fd)


    # def execute(self, memory, registers):
    #     method_ref = memory.dex.lookup_method(self.vB)
    #     call_site_data = memory.dex.
    #
    #     # if self.opcode == 0xfa:
    #     params = [i for i in range(self.vC, self.vC + self.vA)]
    #     memory.method_instr_values = {
    #         'method_ref': method_ref,
    #         'proto_ref': proto_ref,
    #         'is_external_call': True,
    #         'params': params
    #     }


class ConstMethod(InstructionBase):

    def fetch(self) -> None:
        self.prefix = "const-method"
        match self.opcode:
            case 0xfe:
                self.fmt = 0x11222
                self.prefix += "-handle"
            case 0xff:
                self.fmt = 0x11222
                self.prefix += "-type"
            case _:
                raise OpCodeNotFoundError(self.opcode)


    def decode(self, fd):
        self.address = fd.tell() - 1
        (self.vA, self.vB) = self.decode_args(fd)
