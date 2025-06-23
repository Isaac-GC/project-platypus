from enum import Enum

from dex.instructions import Instruction
from dex.method import Method

class ControlFlow(Enum):
    Terminate = 0x1
    GoTo = 0x2
    Branch = 0x3
    FallThrough = 0x4

class CodeBlock:
    """
        This implementation of code block is not synonymous with the documentation. Instead, it
        intends to put most of the base implementation in the Method class with the breaking out of
        instructions and control flow (Goto, TryCatch, etc) into blocks here.

        This will contain all control flow related "blocks" that can then be parsed later or used to
        build a callgraph

        'code_item' Reference: https://source.android.com/docs/core/runtime/dex-format#code-item
    """

    def __init__(self, containing_method: Method):
        self.blocks = []
        self.containing_method = containing_method

    def build_code_flow(self):
        # 'instr_size' should cover this, but just to be safe, we'll do an extra check
        instr_ref: list[Instruction] = self.containing_method.instructions
        addr_lookup = { instr.address: idx for idx, instr in enumerate(instr_ref) }

        if len(instr_ref) != 0:
            for instr in instr_ref:
                match instr.opcode:

                    case opcode if 0xe <= opcode <= 0x11: # Return statements
                        instr.control_flow = ControlFlow.Terminate
                    case opcode if opcode == 0x27: # Throw statement
                        instr.control_flow = ControlFlow.Terminate

                    case opcode if 0x28 <= opcode <= 0x2a: # GotTo Statement
                        instr.control_flow = ControlFlow.GoTo

                    case opcode if 0x32 <= opcode <= 0x3d: # If statements
                        instr.control_flow = ControlFlow.Branch

                    case _:
                        instr.control_flow = ControlFlow.FallThrough







class BasicBlock:
    def __init__(self):
        self.instructions = []
        self.next_branch = None


