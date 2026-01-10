#
#
# -- Start of File --
# | 4 bytes - Magic Bytes | 2 Bytes - module name length | 4 Bytes - Version | 2 Bytes - OffSet start of node/edge map | 4 Bytes - Offset Start of string index
# | X Bytes - "package:module" name |
# | Node/Edge map (2 byte aligned)  |
# | string index map |
# -- End of File --
#
# Creation Guidance
# 1. An initial major and minor version (i.e. `16.1`) will be the initial file
# 2. Subsequent patch levels will be a "patch" file, if no significant differences it will have null bytes filling both offset fields
# 3.
#
#
#
#

import getpass
import os
import struct
import subprocess

from dex.dexfile import DexFile
from dex.clazz import Clazz

# TODO:
#  1. Convert an AAR/dependency to dex using d8
#  2. Index the dexfile
#  3. Convert the dexfile to the above file format
#  4. Map items to parsed apps/APKs

d8_BINARY = f"/Users/{getpass.getuser()}/Library/Android/sdk/build-tools/35.0.0/d8"

def version_str_to_bytes(version_string: str) -> bytes:
    ver_pieces = version_string.split('.')
    return struct.pack(">BBB", ver_pieces[0], ver_pieces[1], ver_pieces[2])

def bytes_to_version_str(byte_string: bytes) -> str:
    major, minor, patch = struct.unpack(">BBB", byte_string)
    return f"{major}.{minor}.{patch}"

def convert_d8_java_dependency(target_filename: str) -> bool:
    if os.path.isfile(target_filename):
        result = subprocess.run([d8_BINARY, target_filename], capture_output=True, text=True)


    else:
        print(f"[-] File doesn't seem to exist. Doublecheck the file name and path.")
        return False