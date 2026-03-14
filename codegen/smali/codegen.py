from dex.clazz import Clazz
# Class is intended to format code in a "normal" type-ish way
#   If code can't be formatted properly, it will error out and just format the raw instructions
#
# Intention is through best effort and additional logic will be implemented to hopefully deobfuscate
# and/or identify unused/dead code

from dex.dexfile import DexFile
from dex.method import Method


class CodeGen:
    def __init__(self, dexfile: DexFile) -> bool:
        dex_file_origin: DexFile = dexfile
        clazzes: dict[str, Clazz] = {}
        methods: dict[str, Method] = {}

        if


    def build_class_map(self) -> dict[str, Clazz]:
        pass

    def __build_method_map(self) -> dict[str, Method]:
        pass