import enum
import logging

from vm.utils import LogHandler

handler = LogHandler()
log = logging.getLogger(__name__)
log.addHandler(handler)
log.setLevel(logging.DEBUG)

class BasicBlockType(enum.Enum):
    RETURN = 0
    THROW  = 1
    GOTO   = 2
    IF     = 3


class BasicBlock:
    def __init__(self):
        self.instructions = []
        self.next_branch = None # (If it branches off)
        self.block_type = BasicBlockType
        self.instr_idx_start = 0

class CodeBlock:
    """
        This implementation of code block is not synonymous with the documentation. Instead, it
        intends to put most of the base implementation in the Method class with the breaking out of
        instructions and control flow (Goto, TryCatch, etc) into blocks here.

        This will contain all control flow related "blocks" that can then be parsed later or used to
        build a callgraph

        'code_item' Reference: https://source.android.com/docs/core/runtime/dex-format#code-item
    """

    def __init__(self, code_item):
        self.blocks = []
        self.code_item = code_item
        self.addr_lookup = {}

    def build_code_flow(self):
        # 'instr_size' should cover this, but just to be safe, we'll do an extra check
        instr_ref = self.code_item.instructions

        num_instrs = len(instr_ref)
        if num_instrs != 0:
            idx = 0
            while idx < num_instrs:
                (block, i) = self.__build_basic_block(idx)
                self.blocks.append(block)
                idx += i


    def __build_basic_block(self, start_idx: int):
        block = BasicBlock()
        block.instr_idx_start = start_idx
        idx = start_idx


        # TODO: This is backwards, a basic block should *start* with the following items, not end with them
        for instr in self.code_item.instructions:
            block.instructions.append(instr)
            idx += 1
            match instr.opcode:
                case opcode if 0xe <= opcode <= 0x11:  # Return statements
                    block.block_type = BasicBlockType.RETURN
                    # return doesn't need to go to another branch, just exit
                    return block, idx

                case opcode if opcode == 0x27:  # Throw statement
                    block.block_type = BasicBlockType.THROW
                    # Should end the run
                    return block, idx

                case opcode if 0x28 <= opcode <= 0x2a:  # GoTo Statement
                    block.block_type = BasicBlockType.GOTO
                    block.next_branch = instr.vB
                    return block, idx

                case opcode if 0x32 <= opcode <= 0x3d:  # If statements
                    block.block_type = BasicBlockType.IF
                    if opcode < 0x38: # Normal if statement
                        block.next_branch = instr.vC
                    else: # If-zero type statements
                        block.next_branch = instr.vB
                    return block, idx

        return block, idx  # This should NEVER occur


    def lookup_codeblock_by_idx_offset(self, idx: int):
        for block in self.blocks:
            if block.instr_idx_start == idx:
                return block
        return None



