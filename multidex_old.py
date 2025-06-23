import hashlib
import io
from typing import BinaryIO, Optional, Dict, List

from dex.dex import Dex
from dex.instructions import *
from vm.mock_handler import try_to_mock_methods


class MultiDex:

    def __init__(self):
        self.dex_files = []
        # self.preload_classes = []
        self.loaded_classes = {}
        self.method_data_dict = {}

    def preload_all_classes(self):
        # Duplicates will be handled here based on classes.dex index
        # (i.e. classes.dex will take precedence over classes3.dex)
        for idx, dex_file in enumerate(self.dex_files):
            for clazz in dex_file.clazzes:
                if clazz.clazz_name not in self.loaded_classes:
                    self.loaded_classes[clazz.clazz_name] = {
                        'clazz': clazz,
                        'source_dex_file': idx,
                    }

    # def build_method_ref_dict(self):
    #
    #     for clazz_name, clazz_data in self.loaded_classes:
    #
    #
    #         current_idx = 0
    #         for virtual_method in clazz_data['class_data']['virtual_methods']:
    #             if not current_idx:
    #                 current_idx = virtual_method.method_idx_diff.value
    #             else:
    #                 current_idx += virtual_method.method_idx_diff.value
    #
    #         clazz_data['class_data']['methods'] = virtual_method
    #             self.method_data[current_idx] = virtual_method
    #
    #         current_idx = 0
    #         for direct_method in clazz_data['class_data']['direct_methods']:
    #             if not current_idx:
    #                 current_idx = direct_method.method_idx_diff.value
    #             else:
    #                 current_idx += direct_method.method_idx_diff.value
    #
    #             self.method_data[current_idx] = direct_method

    def load_dex_file(self, dex_file_path):
        # Internal implementation -- uses custom APK parser
        dex_file = DexFile(dex_file_path)
        self.dex_files.append(dex_file)
        # for clazz in dex_file.clazzes:
        #     pass

    def lookup_clazz(self, clazz_name_lookup):
        for clazz_name, clazz_data in self.loaded_classes:
            if clazz_name == clazz_name_lookup:
                return clazz_data
        return None
    # def load_dex_file_androguard(self):
    #     # Uses androguard to load classes.dex


class DexFile:
    def __init__(self, dex_file_path):
        self.dex_file_path = dex_file_path
        self.dex = Dex.from_file(dex_file_path)

        with open(dex_file_path, 'rb') as fd:
            self.fd = io.BytesIO(fd.read())

        self.__get_dexfile_hash()
        self.classes_filename = dex_file_path.split('/')[-1]
        self.clazzes = []
        self.method_data = {}
        self.build_method_id_to_method_data_dict()

    def __get_dexfile_hash(self):
        md = hashlib.sha256()
        md.update(self.fd.getbuffer())
        self.digest = md.hexdigest()

    def build_class_idx(self):
        for clazz_def_item in self.dex.class_defs:
            tmap = {}

            clazz = clazz_def_item
            tmap['clazz_name'] = clazz.type_name
            tmap['class_data'] = clazz.class_data
            tmap['methods'] = []

            # This is split up to allow for clarity and easier tweaking
            # tmap['direct_methods'] = clazz.class_data.direct_methods
            # tmap['virtual_methods'] = clazz.class_data.virtual_methods
            #
            # tmap['static_fields'] = clazz.class_data.static_fields
            # tmap['instance_fields'] = clazz.class_data.instance_fields

            self.clazzes.append(tmap)

    def build_method_id_to_method_data_dict(self):

        for clazz in self.clazzes:
            clazz['methods'] = []

            current_idx = 0
            for cdata in clazz['class_data']:
                for virtual_method in cdata.virtual_methods:
                    if not current_idx:
                        current_idx = virtual_method.method_idx_diff.value
                    else:
                        current_idx += virtual_method.method_idx_diff.value

                    self.fd.seek(current_idx)
                    mthd = Method(self.fd, self, None)
                    mthd.load_bytecode()
                    clazz['methods'].append(mthd)

                for direct_method in cdata.virtual_methods:
                    if not current_idx:
                        current_idx = direct_method.method_idx_diff.value
                    else:
                        current_idx += direct_method.method_idx_diff.value

                    self.fd.seek(current_idx)
                    mthd = Method(self.fd, self, None)
                    mthd.load_bytecode()
                    clazz['methods'].append(mthd)

    def get_fqfn(self, m_id):
        return f"{self.dex.method_ids[m_id].class_name}.{self.dex.method_ids[m_id].method_name}({self.dex.method_ids[m_id].proto_desc})"

    def get_method_at_offset(self, method_offset: int, execution_flags: Optional[dict]):
        self.fd.seek(method_offset)
        func = Method(self.fd, self.dex, self, execution_flags)
        func.load_bytecode()
        return func

    def call_method_by_id(self, method_id: int, method_args: Optional[List], execution_flags: Optional[dict] = {}):
        # call the static and instance constructor for the class in which the method we called resides
        # TODO: rewrite this so it won't look like a hack
        if not self.static_inits.get(self.dex.method_ids[method_id].class_name, False):
            self.static_inits[self.dex.method_ids[method_id].class_name] = True
            for index, method in enumerate(self.dex.method_ids):
                if method.method_name == "<clinit>" and method.class_name == self.dex.method_ids[method_id].class_name:
                    log.debug("Calling static constructor: " + method.class_name + "->" + method.method_name)
                    self.call_method_at_offset(self.method_data[index].code_off.value)
                if method.method_name == "<init>" and method.class_name == self.dex.method_ids[method_id].class_name:
                    log.debug("Calling constructor: " + method.class_name + "->" + method.method_name)
                    self.call_method_at_offset(self.method_data[index].code_off.value)

        if method_offset := self.method_data[method_id].code_off.value:
            self.call_stack.append(method_id)
            ret = self.call_method_at_offset(method_offset, method_args, execution_flags)
            self.call_stack.pop()
            return ret
        elif (True):
            pass
            # TODO: put multidex code here

    def call_method_at_offset(self, method_offset: int, method_args: Optional[list] = None,
                              execution_flags: Optional[dict] = None):
        self.fd.seek(method_offset)
        method = Method(self.fd, self, execution_flags)
        self.pc = self.fd.tell()
        method.load_bytecode()

        ret_value = None
        if method_args:
            method.v[-len(method_args):] = method_args  # Place parameters in the correct registers. Grows downwards

        current_instruction: Instruction = method.instructions[self.pc]

        # not using isInstance because it's so freaking slow
        while not 0x0e <= current_instruction.opcode <= 0x11 and current_instruction.opcode != 0x27:
            # While instruction isn't a return instructions
            log.debug(f"@{hex(current_instruction.address)}")

            current_instruction.print_instruction()

            # 0x27: raise, 0x28-0x2a: goto, 0x2b-0x31: switch-case jump, 0x32-0x37: Jmp-if, 0x38-0x3d, Jmp-ifZ
            if method.do_branching or not 0x28 <= current_instruction.opcode <= 0x3d:
                instruction_return = current_instruction.execute(self.memory, method.v)

                if instruction_return.is_external_call:
                    fqn = self.dex.method_ids[instruction_return.ret].class_name + "->" + \
                          self.dex.method_ids[instruction_return.ret].method_name
                    params = [method.v[i] for i in instruction_return.parameters]
                    self.pc = super(type(current_instruction), current_instruction).execute(self.memory, method.v).ret
                    log.debug("Calling method: %s" % (fqn + str(params)))
                    # log.info("(0x%x) Calling method: %s" % (self.pc, fqn + str(params)))
                    if not self.method_data.get(instruction_return.ret, None):
                        log.debug("Method ID %s not found, trying translation" % instruction_return.ret)

                        self.memory.last_return = None
                        # we do translation here now
                        try_to_mock_methods(instruction_return.ret, instruction_return.parameters, self, method.v)
                    else:
                        # backup old PC before doing the invoke and switching the stack frame
                        old_pc = self.pc
                        if len(self.call_stack) < 16:
                            if not any([x in fqn for x in self.method_denylist]):
                                self.memory.last_return = self.call_method_by_id(instruction_return.ret, params)
                            else:
                                self.memory.last_return = None
                                log.info("Method in denylist, skipping %s" % (fqn))
                        else:
                            self.memory.last_return = None
                            log.error("Call stack size exceeded for %s" % (
                                        self.dex.method_ids[instruction_return.ret].class_name + "->" +
                                        self.dex.method_ids[instruction_return.ret].method_name))
                        # restore old PC now that we resumed execution
                        self.pc = old_pc
                elif instruction_return:
                    self.pc = instruction_return.ret

                current_instruction = method.instructions[self.pc]
            else:
                # find the next instruction
                self.pc += 2
                while (current_instruction := method.instructions.get(self.pc, None)) is None:
                    self.pc += 2

            method.print_registers()

        current_instruction.print_instruction()

        # this should be a RET or except
        self.pc = current_instruction.execute(self.memory, method.v)

        return self.memory.last_return


class MultiDexVM:

    def __init__(self, multidex: MultiDex):
        self.multidex = multidex

    def call_method(self, method_signature: str, method_args: Optional[list] = None,
                    execution_flags: Optional[dict] = None):
        clazz_signature, method_signature, method_name = self.__parse_full_signature(method_signature)

        clazz = self.multidex.lookup_clazz(clazz_signature)['clazz']

    def __parse_full_signature(self, signature: str):
        # Doublecheck for and remove class identifier
        if signature[0] is not 'L' and '->' not in signature:
            print("Error, could not parse class and method signatures")

        split_signature = signature.split('->')
        clazz_signature = split_signature[0][1:]
        method_signature = split_signature[1]
        method_name = method_signature.split('(')[0]

        return clazz_signature, method_signature, method_name


class Method:
    def __init__(self, fd: BinaryIO, dex: DexFile, execution_flags: Optional[dict]) -> None:
        self.dex_file = dex

        self.registers_size: int = b2i(self.dex_file.fd.read(2))
        self.ins_size: int = b2i(self.dex_file.fd.read(2))
        self.outs_size: int = b2i(self.dex_file.fd.read(2))
        self.tries_size: int = b2i(self.dex_file.fd.read(2))
        self.debug_offset: int = b2i(self.dex_file.fd.read(4))
        self.instr_size: int = b2i(self.dex_file.fd.read(4))
        self.do_branching: bool = True
        if execution_flags:
            self.do_branching = execution_flags.get("do_branching", True)

        self.v = []
        for i in range(0, self.registers_size):
            self.v.append(0)

        self.method_entrypoint_address = fd.tell()

        # self.fqfn = f"{self.dex_file.method_ids[]}"

        # log.debug("Loading method @%s" % hex(vm.fd.tell()))
        # log.debug("\tRegisters\t\t %s" % self.registers_size)
        # log.debug("\tParameters\t\t %s" % self.ins_size)
        # log.debug("\tReturns\t\t\t %s" % self.outs_size)
        # log.debug("\tTries\t\t\t %s" % self.tries_size)
        # log.debug("\tDebug offset\t\t %s" % self.debug_offset)
        # log.debug("\tInstruction count\t\t %s" % self.instr_size)

        self.instructions: Dict[int, Instruction] = {}

    def load_bytecode(self):
        while self.dex_file.fd.tell() - self.method_entrypoint_address < self.instr_size * 2:
            instruction = build_instruction(self.dex_file)

            if not instruction:
                break

            instruction.fetch()
            instruction.decode(self.dex_file.fd)
            self.instructions[instruction.address] = instruction
            instruction.print_instruction()

    def trim_registers(self):
        # Assures all register values fit into the 32 bit. Emulates typical overflow behavior.
        # hack until we can track register types
        self.v[:] = map(lambda x: x & 0xFFFFFFFF, self.v)

        # returns True additional invocations are needed to satisfy the invoke

    def print_registers(self) -> None:
        msg = ""
        for i in range(len(self.v)):
            if isinstance(self.v[i], list):
                if len(self.v[i]) > 0 and isinstance(self.v[i][0], bytes):
                    msg += ("v%s:%s+ " % (i, self.v[i][0][0:8]))
                elif len(self.v[i]) > 0:
                    msg += ("v%s:%s+ " % (i, self.v[i][0:8]))
                else:
                    msg += ("v%s:%s " % (i, self.v[i]))
            else:
                msg += ("v%s:%s " % (i, self.v[i]))
        # log.debug(msg)


def build_instruction(context: DexFile) -> Instruction:
    opcode = b2i(context.fd.read(1))

    if opcode == 0x00:
        pc = context.fd.tell()
        next_opcode = b2i(context.fd.read(1))
        # look ahead for packed switch data
        if next_opcode == 0x01:
            num_elements = b2i(context.fd.read(2))
            _elements_base = b2i(context.fd.read(4))
            _data = context.fd.read(4 * num_elements)
            # TODO: fix hack
            return Nop(0x0)
        # look ahead for packed switch data
        elif next_opcode == 0x02:
            num_elements = b2i(context.fd.read(2))
            _data = context.fd.read(4 * num_elements * 2)
            # TODO: fix hack
            return Nop(0x0)
        # look ahead for the array-data pseudo instruction
        elif next_opcode == 0x03:
            b_per_element = b2i(context.fd.read(2))
            num_elements = b2i(context.fd.read(4))
            _arr_data = context.fd.read(b_per_element * num_elements)
            return Nop(0x0)
        else:
            context.fd.seek(pc)
            return Nop(0x0)
    elif 0x01 <= opcode <= 0x09:
        return Move(opcode)
    elif 0x0a <= opcode <= 0x0d:
        return MoveResult(opcode)
    elif 0x0e <= opcode <= 0x11:
        return Return(opcode)
    elif 0x12 <= opcode <= 0x1c:
        return Const(opcode)
    elif 0x1d <= opcode <= 0x1e:
        return Monitor(opcode)
    elif opcode == 0x1f:
        return CheckCast(opcode)
    elif opcode == 0x20:
        return InstanceOf(opcode)
    elif opcode == 0x21:
        return ArrLength(opcode)
    elif opcode == 0x22:
        return NewInstance(opcode)
    elif 0x23 <= opcode <= 0x26:
        return Array(opcode)
    elif opcode == 0x27:
        return Throw(opcode)
    elif 0x28 <= opcode <= 0x2a:
        return Goto(opcode)
    elif 0x2b <= opcode <= 0x2c:
        return Switch(opcode)
    elif 0x2d <= opcode <= 0x31:
        return Cmp(opcode)
    elif 0x32 <= opcode <= 0x37:
        return If(opcode)
    elif 0x38 <= opcode <= 0x3d:
        return IfZ(opcode)
    elif 0x44 <= opcode <= 0x51:
        return ArrayOp(opcode)
    elif 0x52 <= opcode <= 0x5f:
        return IOp(opcode)
    elif 0x60 <= opcode <= 0x66:
        return SGet(opcode)
    elif 0x67 <= opcode <= 0x6d:
        return SPut(opcode)
    elif 0x6e <= opcode <= 0x72:
        return InvokeKind(opcode)
    elif 0x74 <= opcode <= 0x78:
        return InvokeKindRange(opcode)
    elif 0x7b <= opcode <= 0x8f:
        return UnOp(opcode)
    elif 0x90 <= opcode <= 0xaf:
        return BinOp(opcode)
    elif 0xb0 <= opcode <= 0xcf:
        return BinOp2Addr(opcode)
    elif 0xd0 <= opcode <= 0xe2:
        return BinOpLit(opcode)
    else:
        raise OpCodeNotFoundError(opcode)


class Memory:
    """
    This class implements an execution context for the DVM.
    It includes the execution state information like register values, field values, etc.
    """

    def __init__(self, dex, fd):
        self.last_return = None
        self.static_fields = {}
        self.instance_fields = {}
        self.dex = dex
        self.fd = fd
