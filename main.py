import os
from contextlib import contextmanager
from types import FrameType
from typing import Optional
from androguard.core.bytecodes.apk import APK

import logging
import signal

from rich.console import Console

from codegen.smali.smali_generator import SmaliCodeGen, SmaliClassCodeGen
from multidex_vm import MultiDexVM
from target_helpers import TargetClass
from vm.utils import LogHandler
from vm.vm import VM

handler = LogHandler()
log = logging.getLogger("main")
log.setLevel(logging.DEBUG)
log.addHandler(handler)


class TimeoutException(Exception):
    pass


@contextmanager
def time_limit(seconds: int):
    def signal_handler(_signalnum: int, _frame: Optional[FrameType]):
        raise TimeoutException("Timed out!")

    signal.signal(signal.SIGALRM, signal_handler)
    signal.alarm(seconds)
    try:
        yield
    finally:
        signal.alarm(0)


def test_items(console: Console):
    target_clazz = "hivhi/wfg"
    target_method = 'bihvbhi'

    target = f"L{target_clazz};->{target_method}"

    console.print(f"[+]")
    console.print("[+] Testing with following values")
    console.print(f"[+]      Class -> {target_clazz}")
    console.print(f"[+]      Method -> {target_method}")
    console.print(f"[+]")

    return target_clazz, target_method, target


def run_dalvik_vm(target_apk: APK, target_method: str, target_method_args: Optional[list]):

    app_package_name = target_apk.get_package().replace('.','_')
    package_path = f"{os.getcwd()}/analysis/{app_package_name}"

    # Check if APK is extracted
    if not os.path.exists(package_path):
        os.makedirs(package_path, exist_ok=True)

    # Extract the dex files to load later
    dex_file_names = [df for df in target_apk.get_dex_names()]
    for dex_name in dex_file_names:
        with open(f"{package_path}/{dex_name}", 'wb+') as dex_file:
            dex_file.write(target_apk.get_file(dex_name))


    # vm = MultiDexVM(package_path)
    vm = VM(package_path)
    for dex_file in dex_file_names:
        log.debug(f"Loading {dex_file}")
        vm.add_dex_files(f"{package_path}/{dex_file}")

    log.debug(f"[+] Dex files loaded: {len(vm.dex_files)}")

    # Check to make sure target_method is in correct format
    if target_method[0] != "L":
        target_method = f"L{target_method}"

    method_exists = vm.lookup_method('Lkotlin/jvm/internal/Intrinsics;->fi')
    log.debug(f"Method exists: {False if method_exists is None else method_exists}")
    method = vm.lookup_method(target_method)

    # containing_clazz = vm.get_clazz(method.clazz_name)
    #
    # method_smali = SmaliClassCodeGen(containing_clazz)
    # print(method_smali.format())

    log.debug(f"Calling: {method.clazz_name}->{method.method_name}")

    # x = 0
    # for clazz in vm.lookup_map.keys():
    #     for _ in vm.lookup_map[clazz]:
    #         x += 1

    log.debug(f"[+] A total of {x} methods were added")

    if method:
        ret_val = vm.call_method(method, target_method_args)
        print(ret_val)


if __name__ == '__main__':
    reg_console = Console()
    apk_image = APK('samples/com_bdnef_yuwenhf_grhfesi.apk')

    (tgt_clazz, target_mthd, target) = test_items(console=reg_console)

    run_dalvik_vm(apk_image, target, ["ub/hrg7swpDirI6F5rjLlQ=="])

    # root_logger = logging.getLogger()
    # formatter = JsonFormatter()
    # for handler in root_logger.handlers:
    #     handler.setFormatter(formatter)

    # loggers = [logging.getLogger(name) for name in logging.root.manager.loggerDict]
    # for logger in loggers:
    #     for handler in logger.handlers:
    #         handler.setFormatter(formatter)

    # tgt = TargetClass(apk_image)
    # tgt.find_target_function(tgt_clazz + '/' + target_mthd)
    # tgt.execute_method()
    # for ref in tgt.xrefs:
    #     print(f"{ref['source_class']}->{ref['source_method']} with value {ref['value']}")
