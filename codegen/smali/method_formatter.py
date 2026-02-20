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

    # TODO: Add logic for redirection of basic blocks
    def add_instructions(self, instructions: List[Instruction]):
        num_instructions = len(instructions)
        for i, instr in enumerate(instructions):
            if i == num_instructions - 1:
                self.instructions.append(instr.print_instruction())
            else:
                self.instructions.append(f"{instr}\n") # Add an extra space for readability

    def add_basic_block(self, basic_block: BasicBlock):
