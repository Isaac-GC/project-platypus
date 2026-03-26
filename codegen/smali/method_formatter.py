from typing import List

from dex.code_block import BasicBlock
from dex.instructions import Instruction


class SmaliMethod:
    def __init__(self, method_name, class_namee):
        self.method_name = method_name
        self.class_namee = class_namee

        self.access_flags = []
        self.annotations = []
        self.signature = "" # Not presented, but is queryable for searching
        self.parameters = []
        self.instructions = []

        # This is set up as a dictionary with an int denoting the location of a basic block.
        #   There should never be any duplicates as the int is the order in which the instructions are called
        #   with the "block-type" being used for building in java hydration and only comment-type annotations
        #   in display smali code
        self.blocks = {}

    # TODO: Add logic for redirection of basic blocks
    def add_instructions(self, instructions: List[Instruction], num_instructions: int):
        for i, instr in enumerate(instructions):
            if i == num_instructions - 1:
                self.instructions.append(instr.print_instruction())
            else:
                self.instructions.append(f"{instr}\n") # Add an extra space for readability

    def add_basic_block(self, basic_block: BasicBlock):
        num_instructions = len(basic_block.instructions)


    def __map_basic_blocks(self, basic_blocks: List[BasicBlock]):
        for basic_block in basic_blocks:
            self.blocks[basic_block.instr_idx_start] = {
                'block-type': basic_block.block_type,
                'next-block': basic_block.next_branch
            }

    def add_basic_blocks(self, basic_blocks: List[BasicBlock]):
        block_mapping = []
        for i,block in enumerate(basic_blocks):
            block_mapping.append({
                "block_num": i,
                "block": block,
                "num_instructions": len(block.instructions)
            })
