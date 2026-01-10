import logging
import re
from enum import Enum

from androguard.core.analysis.analysis import ClassAnalysis, MethodAnalysis, Analysis
from androguard.core.bytecodes.apk import APK
from androguard.core.bytecodes.dvm import DalvikVMFormat
from rich.console import Console
from rich.table import Table

from vm.utils import LogHandler
from vm.vm_old import VM

handler = LogHandler()
log = logging.getLogger("main")
log.setLevel(logging.INFO)
log.addHandler(handler)

ktln_chck_not_null = "Lkotlin/jvm/internal/Intrinsics;->checkNotNullExpressionValue(Ljava/lang/Object; Ljava/lang/String;)V"


class OptType(Enum):
    METHOD = "Method"
    CLAZZ = "Class"


class TargetClass:
    def __init__(self, target_apk: APK):
        self.target_clazz_name = ""
        self.target_method_name = ""
        self.apk_data = target_apk

        self.target_method_xrefs = []

        self.clazz: ClassAnalysis = None
        self.method: MethodAnalysis = None
        self.dalvik_vm_format = DalvikVMFormat(target_apk)
        self.clazzes = Analysis(self.dalvik_vm_format).get_classes()

        self.xrefs = []

        self.res_values = self.apk_data.get_android_resources()

    def find_target_function(self, target):
        split_items = target.split('/') if len(target.split('/')) > 1 else target.split('.')
        self.target_clazz_name = "/".join(split_items[0:-1]).encode()
        self.target_method_name = split_items[-1].encode()

        clazz_results = []
        for clazz in self.clazzes:
            clz = clazz.get_class()
            if self.target_clazz_name in clz.get_name():
                clazz_results.append(clz)
                # print(clz.get_name())

        # if len(clazz_results) > 1:
        #     self.__user_choice_if_multiple_options(OptType.CLAZZ, clazz_results)
        # else:
        self.clazz = clazz_results[0]

        mthd_results = []
        for mthd in self.clazz.get_methods():
            # print(mthd.get_name())
            if self.target_method_name in mthd.get_name():
                mthd_results.append(mthd)
                # print(mthd.get_name())

        if len(mthd_results) > 1:
            self.__user_choice_if_multiple_options(OptType.CLAZZ, mthd_results)
        else:
            self.method = mthd_results[0]

        self.__find_all_consuming_code_references()

    def __find_all_consuming_code_references(self):
        # x = 1
        compiled_method = self.clazz.get_name() + b'->' + self.method.get_name()
        arg_descriptor = self.method.get_descriptor()
        print("Target Method: " + compiled_method.decode() + arg_descriptor.decode())
        arguments = [self.__argument_parser(arg_descriptor.decode())]
        # print(arguments)
        for clz in self.clazzes:
            for mth in clz.get_methods():
                # if x == 1:
                # code = mth.get_method().get_code()

                instr_dict = {idx: instr for idx, instr in enumerate(mth.get_method().get_instructions())}
                instrs = list(instr_dict.values())

                iidx = []
                for idx, val in enumerate(instrs):
                    instr_display = val.show_buff(idx)
                    if compiled_method.decode() in instr_display:
                        iidx.append(idx)

                if len(iidx) != 0:
                    # print("\n\n")
                    # print("# " * 30)
                    # print(mth.class_name, "->", mth.get_method().get_name())

                    # print(f"{instr_dict[iidx-1]} -> {instr_dict[iidx]}")

                    # This needs to be smarter...
                    # vals = []
                    kotlin_offset = 0  # used to skip "kotlin intrinsic-type items"
                    num_args = len(arguments)
                    # print("Num instructions: ", len(instrs))
                    # print("Num Args: ", len(arguments))
                    # print(instrs)
                    for i in iidx:
                        vals = []
                        # print(instrs[i].get_name())
                        # relevant_instrs = instrs[i-1:i-num_args]
                        # print(relevant_instrs)
                        if num_args == 1:
                            args = self.__parse_instructions_and_registers(instrs, i, num_args)
                        else:
                            args = self.__parse_instructions_and_registers(instrs, i, num_args)
                        # print(args)
                        for v in args:
                            if v:
                                if v.startswith('-') and v[1:].isdecimal():
                                    vals.append(int(v))
                                elif v.isdecimal():
                                    vals.append(int(v))
                                elif v[0] == '"':
                                    # Removes unnecessary `"` wrappers
                                    vals.append(v[1:-2])
                                elif '/R$' in v:
                                    self.get_rstring_package_and_name_from_signature(v)
                                else:
                                    vals.append(v)
                            else:
                                vals.append(v)

                        # val = self.__parse_instructions_and_registers(instrs[iidx-1], iidx)
                        # method_name = self.__parse_instructions_and_registers(instr_dict[iidx])
                        self.xrefs.append({
                            'iidx': iidx,  # Prevent duplicates occurrences
                            'value': vals,
                            'source_method': mth.get_method().get_name(),
                            'source_class': mth.get_method().get_class_name()
                        })

    def __user_choice_if_multiple_options(self, opt_type: OptType, vals: list):
        num_choices = len(vals)
        title = ""
        if opt_type.name is OptType.METHOD:
            title = f"{num_choices} Methods found"
        elif opt_type.name is OptType.CLAZZ:
            title = f"{num_choices} Classes found"

        table = Table(title=title)
        table.add_column('Choice')
        table.add_column(f"{opt_type.value} name", justify='center')

        for i, v in enumerate(vals):
            table.add_row(f"{i}", v.get_name().decode())  # Choice Num, Method/Class name

        choice_console = Console()

        ret_successfully = False
        while not ret_successfully:

            choice_console.print(table)
            choice = choice_console.input("\nWhich item do you want to use? ")

            try:
                if OptType.CLAZZ:
                    self.clazz = vals[int(choice)]
                elif OptType.METHOD:
                    self.method = vals[int(choice)]
                ret_successfully = True
            except:
                choice_console.clear()
                print("\n\nOption chosen doesn't appear to be available, please try again\n")

    def __argument_parser(self, full_arguments: str):
        parsed_args = []
        # arguments = [*arguments]
        arguments = full_arguments[full_arguments.index('(') + 1:full_arguments.index(")")]
        print(arguments)
        arg_types = ["B", "S", "I", "J", "F", "D", "Z", "C"]
        idx = 0
        is_object = False
        is_array = False
        for i, c in enumerate(arguments):
            if is_object:
                # End of object
                if c == ";":
                    # If an array of Object types
                    temp = arguments[idx:i + 1]
                    if is_array:
                        parsed_args.append(f"[{temp}")
                        is_array = False
                        idx = i + 1  # idx should start at next char
                    else:
                        return "".join(temp)
                    is_object = False

            elif is_array:
                if c in arg_types:
                    parsed_args.append(f"[{c}")
                    is_array = False
                    idx = i + 1  # idx should start at next char
            else:
                # start of object
                if c == "L":
                    idx = i  # idx should start at current char JIC
                    is_object = True
                # start of an array
                elif c == '[':
                    is_array = True
                elif c in arg_types:
                    parsed_args.append(arguments[i])
            # Last case is unknown value, so...
        return parsed_args

    def __parse_instructions_and_registers(self, instructions, iidx, num_args):
        # Trace the register backwards until the item set in the register is either directly set
        #  or retrieved from "R" strings (or something like that)

        args = []

        curr_instr = instructions[iidx]
        reversed_instructions = instructions.copy()
        reversed_instructions.reverse()

        # Make sure we start at the right place
        curr_instr_idx = reversed_instructions.index(curr_instr) + 1
        for arg in range(num_args):
            # curr_instr_idx -= 1
            arg_value = self.__find_argument(reversed_instructions, curr_instr_idx)
            args.append(arg_value)

        return args

    def __find_argument(self, instructions, idx):
        kotlin_skipper = False
        for ins in instructions[idx:]:
            # print(type(ins.get_name()),ins.get_name())
            vals = ins.show_buff(instructions.index(ins))
            if kotlin_skipper:
                if "sget" in ins.get_name():
                    return vals.split(', ')[1]
                # Find "sget" mnemonic
            elif ktln_chck_not_null in vals:
                kotlin_skipper = True
            # Fix and make "smarter" by detecting the appropriate type
            elif "const" in ins.get_name():
                return vals.split(', ')[1]

    def get_rstring_package_and_name_from_signature(self, item_signature):
        # Break up the item signature and remove empty strings
        splt_items = [s for s in re.split(r'[L(?:;\->)]', item_signature) if s]
        fixed_pkg_name = ".".join(splt_items[0].split('/')[:-1])
        return self.res_values.get_string(fixed_pkg_name, splt_items[1])

    def lookup_string_resource_item_by_id(self, string_id):
        str_name = re.split(r'[@:/]', self.res_values.get_resource_xml_name(string_id))
        print(self.res_values.get_string(str_name[1], str_name[3]))
        return self.res_values.get_string(str_name[1], str_name[3])[1]

    def lookup_string_resource_item_by_package_and_name(self, pkg_name, item_name):
        pass

    # def kotlin_instructions_handler(selfs, instructions, iidx):
    #
    #     if instructions[iidx] == ""

    def execute_method(self):
        all_dex_bytes = self.apk_data.get_dex()
        self.vm = VM("samples/com_bdnef_classes.dex")

        target_method_call = f"{self.clazz.get_name().decode()}->{self.method.get_name().decode()} "

        log.info("[+] Starting katalina VM")
        log.info("[+]")
        log.info(f"[+] Trying to execute {target_method_call} on a total of {len(self.xrefs)} methods")

        x = 1
        for ref in self.xrefs:
            parameters = []
            # if x == 1:

            # Prevent bugs from hindering analysis process
            if not ref['value']:
                print \
                    (f"Encountered issues using {ref['source_class']}->{ref['source_method']} with value {ref['value']}")
                continue
                # log.error(f"Encountered issues using {ref['source_class']}->{ref['source_method']} with value {ref['value']}")

            else:
                parameters = ref['value']
                for v in ref['value']:
                    if v:
                        if v.startswith('-') and v[1:].isdecimal():
                            parameters.append(int(v))
                        elif v.isdecimal():
                            parameters.append(int(v))
                        elif v[0] == '"':
                            parameters.append(v[1:-2])
                        else:
                            parameters.append(v)
                    else:
                        parameters.append(v)
                # print(parameters)

            print("made it this far")
            for indx, mthd in enumerate(self.vm.dex.method_ids):
                if f"{mthd.class_name}->{mthd.method_name}" in f"{ref['source_class']}->{ref['source_method']}":
                    print(f"Found class/method {ref['source_class']}->{ref['source_method']} @ idx: {indx}")

                # print(parameters)
                # else:
                #     for v in ref['value']:
                #         if v:
                #             if v.startswith('-') and v[1:].isdecimal():
                #                 parameters.append(int(v))
                #             elif v.isdecimal():
                #                 parameters.append(int(v))
                #             elif v[0] == '"':
                #                 parameters.append(v[1:-2])
                #             else:
                #                 parameters.append(v)
                #         else:
                #             parameters.append(v)
                #     print(parameters)

                # if len(parameters) == 1:
                #     parameters = parameters[0]
                ###

                # Fix this logic to prevent duplicate calls
                # for indx, mthd in enumerate(self.vm.dex.method_ids):
                #
                #     if f"{mthd.class_name}->{mthd.method_name}" in f"{target_method_call}":
                #         try:
                #             args_type = "".join([str(p.value) for p in mthd.proto_id.params_types.list])
                #         except AttributeError:
                #             print((f"Failed to parse arg types of \
                #             {mthd.class_name}->{mthd.method_name}"))
                #
                #         # try:
                #             # print(f"[+] Calling {self.vm.dex.method_ids[indx].class_name}->{self.vm.dex.method_ids[indx].method_name} with parameters: {parameters}")
                #         return_val = self.vm.call_method_by_id(indx, parameters)
                #         print("Return: ",return_val)
                #
                #         # print(ret)
                #         log.info \
                #             (f"[+] {ref['source_class']}->{ref['source_method']}\n             return value: {str(return_val)}\n")
                # except Exception as ex:
                #     print(str(ex))
