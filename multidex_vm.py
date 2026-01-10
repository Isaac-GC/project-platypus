#!/usr/bin/env python
import importlib
import inspect
import io
import logging
import pkgutil
import re

from dex.instructions import *
from dex.method import Method
from vm.memory import Memory
from vm.mock_handler import try_to_mock_methods
from vm.utils import LogHandler
from dex.dex import Dex
from dex.dexfile import DexFile


from typing import Optional, List, BinaryIO, Tuple

handler = LogHandler()
log = logging.getLogger(__name__)
log.addHandler(handler)
log.setLevel(logging.DEBUG)


# log.setLevel(logging.DEBUG)
# log.setLevel(logging.ERROR)

method_parser_regex = re.compile(r"^(.*)->(.*)(?:\((.*)\)(.*)$)?")

class MultiDexVM:
    def __init__(self, dex_file_path, deny_list=[]):
        self.dex_file_path = dex_file_path
        self.dex_files = []

        self.static_inits = {}
        self.lookup_map = {}
        self.call_stack = []

        self.memory: Memory = Memory()
        self.method_denylist = deny_list

        self.__register_mocked_methods()

    def __register_mocked_methods(self):
        mocks_package = "vm.mocks"
        package = importlib.import_module(mocks_package)

        for _, modname, _ in pkgutil.walk_packages(
            package.__path__,
            package.__name__ + ".",
            onerror=lambda x: None
        ):
            try:
                importlib.import_module(modname)
            except ImportError as ie:
                log.error(f"Could not import {modname}")


    def add_dex_files(self, dex_file_path):
        fd = open(dex_file_path, 'rb')
        log.debug(f"[+] Adding {dex_file_path}")
        dex_file = DexFile(dex_file_path)
        self.dex_files.append(dex_file)
        x = 0
        for clazz, mthds in dex_file.lookup_map.items():
            if clazz not in self.lookup_map:
                # log.debug(f"Adding {clazz} to lookup map")
                x += 1
                self.lookup_map[clazz] = mthds # Add the class and its methods
            else:
                log.debug(f"[-] Skipping adding {clazz}")
        log.debug(f"[+] Added {x} items")

    def print_call_stack(self):
        if log.level <= logging.DEBUG:
            indent = ""
            for m_id in self.call_stack:
                indent += " "
                print(f"{indent}> {self.get_fqfn(m_id)})")

    def get_fqfn(self, method: Method):
        return f"{method.clazz_name}.{method.method_name}({method.params})"

    def lookup_method(self, method_signature):
        (clazz, mthd, args, ret_vals) = self.parse_method(method_signature)
        # print(f"Found\n  Class: {clazz},  Method: {mthd}")

        # Trim/fix the class name
        if clazz[0] != "L":
            clazz = clazz[1:]
            # log.debug(f"Adding 'L' item to class {clazz}")
        if clazz[-1] != ";":
            clazz = clazz[:-1]
            # log.debug(f"Adding ';' item to class {clazz}")


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


    def call_method(self, method: Method, method_args: Optional[list], execution_flags: Optional[dict] = None):
        ret_value = None
        if method_args:
            # Place parameters in the correct registers. Grows downwards
            method.registers[-len(method_args):] = method_args

        self.memory.dex = method.dex

        instr_ptr = 0
        curr_instr: Instruction = method.instructions[instr_ptr]

        log.debug(f"Current Instruction: {curr_instr.prefix}{curr_instr.suffix}")

        # Iterate until a return instruction is encountered (ignoring 'isInstance' because it's slow for r/n)
        while not 0x0e <= curr_instr.opcode <= 0x11 and curr_instr.opcode != 0x27:
            log.debug(f"@{hex(curr_instr.opcode)}")
            curr_instr.print_instruction()

            # 0x27: raise, 0x28-0x2a: goto, 0x2b-0x31: switch-case jump, 0x32-0x37: Jmp-if, 0x38-0x3d, Jmp-ifZ
            if method.do_branching or not 0x28 <= curr_instr.opcode <= 0x3d:
                instruction_ret_value = curr_instr.execute(self.memory, method.registers)
                instr_ptr += 1

                if instruction_ret_value and instruction_ret_value.is_external_call:
                    fqn = method.clazz_name + "->" + method.method_name
                    print(method.registers)
                    print(f"{instruction_ret_value.ret} || {instruction_ret_value.parameters}")
                    params = [method.registers[i] for i in instruction_ret_value.parameters]
                    curr_instr = super(type(curr_instr), curr_instr).execute(self.memory, method.registers).ret

                    log.debug("Calling method: %s" % (fqn + str(params)))
                    # log.info("(0x%x) Calling method: %s" % (self.pc, fqn + str(params)))

                    if isinstance(instruction_ret_value.ret, int):
                        ret_val = self.get_method_by_id(instruction_ret_value.ret)
                        if not ret_val:
                            log.debug("Method %s not found, trying translation" % instruction_ret_value.ret)

                            self.memory.last_return = None # Forget it and try seeing if there is mock method for it
                            try_to_mock_methods(instruction_ret_value.ret, instruction_ret_value.parameters, self, method.registers)
                            curr_instr = method.instructions[instr_ptr]
                    else:
                        if len(self.call_stack) < 16:
                            if not any([dm in fqn for dm in self.method_denylist]):
                                self.memory.last_return = self.call_method(instruction_ret_value.ret, params)
                            else:
                                self.memory.last_return = None
                                log.info(f"Method in denylist, skipping {fqn}")
                        else:
                            self.memory.last_return = None
                            log.error(f"Call stack size exceeded for {instruction_ret_value.ret}")

                        curr_instr = method.instructions[instr_ptr]


                elif instruction_ret_value:
                    print(instruction_ret_value.ret)
                    curr_instr = method.instructions[instruction_ret_value.ret]

                # else:
                #     instr_ptr += 1
                #     curr_instr = method.instructions[instr_ptr]

                curr_instr = method.instructions[instr_ptr]

            else:
                instr_ptr += 1
                curr_instr = method.instructions[instr_ptr]
                # while(curr_instr := method.instructions.get("", None)) is None:

            method.print_registers()

        curr_instr.print_instruction()

        # This should be a RET or EXCEPT
        curr_instr.execute(self.memory, method.params)
        return self.memory.last_return

    # TODO: Cleanup, this can simplified even further
    def get_method_by_signature(self, method_signature):
        method: Method = self.lookup_method(method_signature)

        if method:
            if method.clazz_name not in self.static_inits:
                if method.method_name == "<clinit>":
                    log.debug(f"Calling static constructor: {method.clazz_name}->{method.method_name}")

                if method.method_name == "<init>":
                    log.debug(f"Calling constructor: {method.clazz_name}->{method.method_name}")

            if not method.is_native() and not method.is_abstract():
                return method

            else:
                # Returns nothing. Need to implement abstract method construction and native method calling
                # TODO: Abstract Method Construction
                #
                # TODO: Native Method handling/calling
                return None

        return None