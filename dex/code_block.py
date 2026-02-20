import logging

from vm.utils import LogHandler

handler = LogHandler()
log = logging.getLogger(__name__)
log.addHandler(handler)
log.setLevel(logging.DEBUG)



class CodeBlock:
    """
        This implementation of code block is not synonymous with the documentation. Instead, it
        intends to put most of the base implementation in the Method class with the breaking out of
        instructions and control flow (Goto, TryCatch, etc) into blocks here.

        This will contain all control flow related "blocks" that can then be parsed later or used to
        build a callgraph

        'code_item' Reference: https://source.android.com/docs/core/runtime/dex-format#code-item
    """

    def __init__(self, containing_method):
        self.blocks = []
        self.containing_method = containing_method
        self.addr_lookup = {}

    def build_code_flow(self):
        # 'instr_size' should cover this, but just to be safe, we'll do an extra check
        instr_ref = self.containing_method.instructions
        # self.addr_lookup = { instr.address: idx for idx, instr in enumerate(instr_ref) }

        # if self.containing_method.clazz_name == "Lhivhi/wfg;":
        #     if self.containing_method.method_name == "bihvbhi":
        #         log.setLevel(logging.DEBUG)
        # else:
        #     log.setLevel(logging.INFO)

        basic_block = BasicBlock()
        if len(instr_ref) != 0:
            for idx, instr in enumerate(instr_ref):
                # log.debug(f"Adding instruction {instr.prefix}")

                match instr.opcode:

                    case opcode if 0xe <= opcode <= 0x11: # Return statements
                        self.blocks.append(basic_block)
                        basic_block = BasicBlock()
                        basic_block.instr_idx_start = idx + 1 # (Next Instruction)

                    case opcode if opcode == 0x27: # Throw statement
                        self.blocks.append(basic_block)
                        basic_block = BasicBlock()
                        basic_block.instr_idx_start = idx + 1 # (Next Instruction)

                    case opcode if 0x28 <= opcode <= 0x2a: # GoTo Statement
                        self.blocks.append(basic_block)
                        basic_block = BasicBlock()
                        basic_block.instr_idx_start = idx + 1 # (Next Instruction)

                    case opcode if 0x32 <= opcode <= 0x3d: # If statements
                        self.blocks.append(basic_block)
                        basic_block = BasicBlock()
                        basic_block.instr_idx_start = idx + 1 # (Next Instruction)

                    case _:
                        basic_block.instructions.append(instr)


    def lookup_codeblock_by_idx_offset(self, idx: int):
        for block in self.blocks:
            if block.instr_idx_start == idx:
                return block
        return None


class BasicBlock:
    def __init__(self):
        self.instructions = []
        self.next_branch = None # (If it branches off)
        self.instr_idx_start = 0




