
from dex.clazz import Clazz
from dex.helpers import sign_extend
from dex.instructions_new import InstructionBase
from dex.method import Method


# Class is intended to format code in a "normal" type-ish way
#   If code can't be formatted properly, it will error out and just format the raw instructions
#
# Intention is through best effort and additional logic will be implemented to hopefully deobfuscate
# and/or identify unused/dead code
#
# Kudos to JADX as it was used heavily for reference in building the smali code/flow

class SmaliCodeGen:
    def __init__(self, method: Method):
        self.method = method
        self._label_map: dict[int, list[str]] = {}

    def _build_labels(self):
        for instr in self.method.instructions:
            op = instr.opcode

            if 0x28 <= op <= 0x2a: # Goto
                target = instr.codepoint + sign_extend(instr.vA, {0x28: 8, 0x29: 16, 0x2a: 32}[op])
                self._add_label(target, f":goto_{target:x}")

            elif 0x32 <= op <= 0x37: # If/Conditional
                target = instr.codepoint + sign_extend(instr.vC, 16)
                self._add_label(target, f":cond_{target:x}")

