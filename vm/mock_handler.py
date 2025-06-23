import logging
import re
from typing import Callable

from dex.method import Method
from vm.utils import LogHandler

rfmt_regex = re.compile(r"->")

handler = LogHandler()
log = logging.getLogger(__name__)
log.addHandler(handler)
log.setLevel(logging.INFO)

MOCKS_REGISTRY = {}

# Saves data for between mocked method calls
STATE_DATA = {}

# Needs the VM reference passed into mocked method
METHOD_VM_NEEDED = [
    'Ljava_lang_Thread_getStackTrace'
]

def register_mock(func):
    # Fix the module path so it mimics Java's path pattern
    #   --> Should end up looking like: "some_path_Class_doSomething"
    cfqn = func.__module__.split('.')
    cfqn[-1] = convert_to_camel_case(cfqn[-1])

    mqn = []
    for i in cfqn:
        if i not in ['vm','mocks']:
            mqn.append(i)
    fmqn = ".".join(mqn)

    if func.__qualname__[0] == '_':
        ffqn = func.__qualname__[1:]
    else:
        ffqn = func.__qualname__

    module_path = f"{fmqn}.{ffqn}".replace('.','_')
    MOCKS_REGISTRY[f"L{module_path}"] = func
    return func


# The vm parameter is probably not used, but its added here JIC
def execute_mocked_method(fcqn, mocked_method: Callable, params, vm, registers):
    args = [ registers[param] for param in params ]

    if fcqn in METHOD_VM_NEEDED:
        ret_val = mocked_method(args, STATE_DATA, vm)
    else:
        ret_val = mocked_method(args, STATE_DATA)

    # TODO: Add verification the method processed correctly or handle issues/errors accordingly
    return ret_val

def try_to_mock_methods(method, params: list, multi_dex_vm, registers):
    method_fqn = None
    match method:
        case Method(): method_fqn = method.signature
        case int():
            mthd_ref = multi_dex_vm.memory.dex.method_ids[method]
            method_fqn = f"{mthd_ref.class_name}->{mthd_ref.method_name}"
        case _:
            method_fqn = None


    if method_fqn:
        try:
            str_params = [str(registers[param])[0:8] for param in params]
        except IndexError:
            str_params = params

        log.debug(f"Translating method: "
                  f"{method_fqn} "
                  f"with {str_params}")

        mthd_rfmtg = rfmt_regex.split(method_fqn)
        clazz_name = mthd_rfmtg[0].replace('/', '_').replace(';','')
        method_name = mthd_rfmtg[1].replace('<', '0').replace('>', '0')
        fcqn = f"{clazz_name}_{method_name}"

        mocked_method = MOCKS_REGISTRY.get(fcqn, None)
        mmthd = MOCKS_REGISTRY
        mthd_result = execute_mocked_method(fcqn, mocked_method, params, multi_dex_vm, registers)
        multi_dex_vm.memory.last_return = mthd_result



def convert_to_camel_case(some_str: str):
    return "".join([f"{s[0].upper()}{s[1:]}" for s in some_str.split('_')])
