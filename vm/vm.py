import importlib
import logging
import pkgutil
import re
from typing import Optional

from dex.code_block import BasicBlock, EdgeKind
from dex.dexfile import DexFile
from dex.instructions_new import ControlFlow
from dex.method import Method
from vm.memory import Memory
from vm.mock_handler import try_to_mock_methods
from vm.utils import LogHandler

handler = LogHandler()
log = logging.getLogger(__name__)
log.addHandler(handler)
log.setLevel(logging.INFO)
# log.setLevel(logging.DEBUG)

method_parser_regex = re.compile(r"^(.*)->(.*)(?:\((.*)\)(.*)$)?")

class VM:
    def __init__(self, dex_file_path):
        self.dex_file_path = dex_file_path
        self.__register_mocked_methods()

        self.call_stack = [] # Normal call stack (method calls method... calls method... etc)
        self.dex_files = [] # Loaded dex file content
        self.lookup_map = {} # Combined Multidex clazz/method lookup
        self.memory = Memory()

        self.method_denylist = []

        self.starting_target_method = None # TODO: Change later to be whats defined in the Android Manifest
        self.starting_args = []

    def __register_mocked_methods(self):
        mocks_package = "vm.mocks"
        package = importlib.import_module(mocks_package)

        for _, modname, _ in pkgutil.walk_packages(
                package.__path__,
                package.__name__ + ".",
                onerror=lambda e: None
        ):
            try:
                importlib.import_module(modname)
            except ImportError:
                log.error(f"Could not import {modname}")


    def add_dex_files(self, dex_file_path):
        log.debug(f"[+] Adding {dex_file_path}")
        dex_file = DexFile(dex_file_path)
        self.dex_files.append(dex_file)

        x = 0
        for clazz, mthds in dex_file.lookup_map.items():

            # Currently, this means if there is some duplicate clazz in later dex files, it won't get added
            if clazz not in self.lookup_map:
                x += 1
                self.lookup_map[clazz] = mthds
            else:
                log.debug(f"[-] Skipping {clazz}")

        log.debug(f"[+] Added {x} classes")

    def get_fqfn(self, method: Method):
        return f"{method.clazz_name}.{method.method_name}({method.params})"

    def print_call_stack(self):
        if log.level <= logging.DEBUG:
            indent = ""
            for m_id in self.call_stack:
                indent += " "
                print(f"{indent} ↳ {self.get_fqfn(m_id)}")


    def _check_clazz_name_fmt(self, clazz: str):
        # Trim/fix the class name
        if clazz[0] != "L":
            clazz = clazz[1:]
            # log.debug(f"Adding 'L' item to class {clazz}")
        if clazz[-1] != ";":
            clazz = clazz[:-1]
            # log.debug(f"Adding ';' item to class {clazz}")

        return clazz

    def get_clazz(self, clazz_name: str):
        clazz = self._check_clazz_name_fmt(clazz_name)
        if clazz in self.lookup_map:
            return self.lookup_map[clazz]['clazz']
        return None

    def lookup_method(self, method_signature):
        (clazz, mthd, args, ret_vals) = self.parse_method(method_signature)
        # print(f"Found\n  Class: {clazz},  Method: {mthd}")
        clazz = self._check_clazz_name_fmt(clazz)

        log.debug(f"Looking up class: {clazz} and {mthd}")
        # print(self.lookup_map)
        if clazz in self.lookup_map:
            log.debug(f"Found class: {clazz}")
            if mthd in self.lookup_map[clazz]:
                log.debug(f"Found method: {mthd}")
                return self.lookup_map[clazz][mthd]
        return None


    def parse_method(self, method_signature: str):
        vals = method_parser_regex.match(method_signature)
        return (vals.group(1),  # Class
               vals.group(2),   # Method
               vals.group(3),   # Arguments
               vals.group(4))   # Return Value

    def get_method_by_id(self, method_id):
        for d in self.dex_files:
            if method_id in d.lookup_by_id_map:
                return d[method_id]
        return None

    def call_method(self, method: Method, method_args: Optional[list]):
        if method_args:
            # Place parameters in the correct registers. Grows downwards
            method.registers[-len(method_args):] = method_args

        self.memory.dex = method.dex # Whatever dex file the method came from originally (helps with lookups)
        self.call_stack.append(method) # Append the current method. Only necessary for tracking purposes

        log.debug(f"Calling: {method.clazz_name}->{method.method_name}")
        log.debug(f"[+] method has {len(method.code_block.blocks)} code blocks")


        # Start at the entry block, then follow CFG edges
        current_block = method.code_block.entry
        while current_block is not None:
            current_block = self.execute_basic_block(current_block)

        self.call_stack.pop()
        return self.memory.last_return

    def execute_basic_block(self, block: BasicBlock):
        curr_method = self.call_stack[-1]
        for instr in block.instructions:

            # instr.print_instruction()

            # Execute the instruction and let's see what happens
            instr_val = instr.execute(self.memory, curr_method.registers)

            # We don't care about what the instruction does here, only what its outcome is
            match instr.control_flow:
                case ControlFlow.GoTo:
                    target_codepoint = block.next_branch
                    target_block = curr_method.code_block.lookup_codeblock_by_codepoint(target_codepoint)
                    if target_block:
                        return target_block
                    log.error(f"GOTO target {target_codepoint:#x} not found")
                    return None

                case ControlFlow.Branch:
                    taken_codepoint = self.memory.last_return
                    if taken_codepoint:
                        if taken_codepoint != 1:
                            target_block = curr_method.code_block.lookup_codeblock_by_codepoint(taken_codepoint)
                            if target_block:
                                return target_block
                    fall = next((e.target for e in block.successors if e.kind == EdgeKind.FALL_THROUGH), None)
                    return fall

                case ControlFlow.FallThrough:
                    if instr.opcode in (0x2b, 0x2c):
                        taken_codepoint = self.memory.last_return
                        if taken_codepoint:
                            target_block = curr_method.code_block.lookup_codeblock_by_codepoint(taken_codepoint)
                            if target_block:
                                return target_block
                        fall = next((e.target for e in block.successors if e.kind == EdgeKind.FALL_THROUGH), None)
                        return fall

                    if instr_val and instr_val.is_external_call:
                        fqn = curr_method.clazz_name + "->" + curr_method.method_name
                        params = [curr_method.registers[i] for i in instr_val.parameters]

                        if isinstance(instr_val.ret, int):
                            ret_val = self.get_method_by_id(instr_val.ret)
                            if not ret_val:
                                log.debug(f"Method {instr_val.ret} not found, trying translation")

                                self.memory.last_return = None  # Forget it and try seeing if there is mock method for it
                                try_to_mock_methods(instr_val.ret, instr_val.parameters, self, curr_method.registers)

                        elif instr_val.ret is not None: # direct method ref
                            if len(self.call_stack) >= 16: # safety, may break things
                                self.memory.last_return = None
                                log.error(f"Call stack depth exceeded at {curr_method.clazz_name}->{curr_method.method_name}")

                            elif any([denied_method in fqn for denied_method in self.method_denylist]):
                                self.memory.last_return = None
                                log.info(f"Method in denylist, skipping {fqn}")
                            else:
                                self.call_method(instr_val.ret, params)

                # Just end it right here, right now.
                case ControlFlow.Terminate:
                    return None

        fall = next((e.target for e in block.successors if e.kind == EdgeKind.FALL_THROUGH), None)
        return fall # Worst case scenario, should never happen... probably should make into a try/except statement


    # TODO: Consider adding ability to debug or add "injection"/"hooking" points
    def setup_vm(self, target_method, args: Optional[list]):
        la_method = self.lookup_method(target_method.method_signature)
        if args and len(args) > 0:
            self.starting_target_method = la_method
            self.starting_args = args



    # Unsure what else needs to be handled, but leaving this as a starting point
    def start_vm(self):
        if self.starting_target_method:
            if len(self.starting_args) > 0:
                self.call_method(self.starting_target_method, self.starting_args)
            else:
                self.call_method(self.starting_target_method, [])
