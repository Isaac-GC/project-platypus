import enum
from dataclasses import dataclass

from codegen.opcode_helper import BRANCH_OFFSET_BITS, resolve_branch_target
from dex.helpers import sign_extend

BRANCH_OPCODES = set(BRANCH_OFFSET_BITS.keys())

class LabelKind(enum.Enum):
    GOTO     = "goto"
    COND     = "cond"
    CATCH    = "catch"
    CATCHALL = "catchall"
    PSWITCH  = "pswitch"
    SSWITCH  = "sswitch"
    ARRAY    = "array"


@dataclass
class Label:
    kind: LabelKind
    offset: int

    @property
    def name(self):
        return f":{self.kind}{self.offset:x}"


class Labels:
    def __init__(self):
        self.labels: dict[int, list[Label]] = {}

    def __add(self, offset: int, kind: LabelKind):
        label = Label(kind, offset)
        self.labels.setdefault(offset, []).append(label)

    def collect_labels(self, instrs: list):
        for instr in instrs:
            op = instr.opcode

            if op not in BRANCH_OPCODES:
                continue

            target = resolve_branch_target(instr)

            if op in (0x28, 0x29, 0x2a):
                self.__add(target, LabelKind.GOTO)
            elif op in (0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
                        0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d):
                self.__add(target, LabelKind.COND)
            elif op == 0x2b:
                instr_cu = instr.codepoint
                for rel_target in instr.switch_table.values():
                    self.__add(instr_cu + rel_target, LabelKind.PSWITCH)
            elif op == 0x2c:
                instr_cu = instr.codepoint
                for rel_target in instr.switch_table.values():
                    self.__add(instr_cu + rel_target, LabelKind.SSWITCH)
            elif op == 0x26:
                self.__add(target, LabelKind.ARRAY)





