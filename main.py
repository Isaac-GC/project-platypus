from contextlib import contextmanager
from types import FrameType
from typing import Optional
from androguard.core.bytecodes.apk import APK

import logging
import signal

from rich.console import Console

from target_helpers import TargetClass
from vm.utils import LogHandler

handler = LogHandler()
log = logging.getLogger("main")
log.setLevel(logging.INFO)
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

    console.print(f"[+]")
    console.print("[+] Testing with following values")
    console.print(f"[+]      Class -> {target_clazz}")
    console.print(f"[+]      Method -> {target_method}")
    console.print(f"[+]")

    return target_clazz, target_method


if __name__ == '__main__':
    reg_console = Console()
    apk_image = APK('samples/com_bdnef_yuwenhf_grhfesi.apk')

    (tgt_clazz, target_mthd) = test_items(console=reg_console)

    # root_logger = logging.getLogger()
    # formatter = JsonFormatter()
    # for handler in root_logger.handlers:
    #     handler.setFormatter(formatter)

    # loggers = [logging.getLogger(name) for name in logging.root.manager.loggerDict]
    # for logger in loggers:
    #     for handler in logger.handlers:
    #         handler.setFormatter(formatter)

    tgt = TargetClass(apk_image)
    tgt.find_target_function(tgt_clazz + '/' + target_mthd)
    tgt.execute_method()
    # for ref in tgt.xrefs:
    #     print(f"{ref['source_class']}->{ref['source_method']} with value {ref['value']}")
