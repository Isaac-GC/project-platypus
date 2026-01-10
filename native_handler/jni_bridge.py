import os
import sys

from elftools.elf.elffile import ELFFile
from unicorn import *
from unicorn.arm64_const import *

# Syscall table reference: https://arm64.syscall.sh/

def log_print(tag, title_ctx="", message=""):
    if message != "":
        print(f"[{tag}] {title_ctx} {message}")
    else:
        print(f"[{tag}] {title_ctx} ")

class JniBridge:

    def __init__(self, verbose=True):
        self.verbose = verbose

        # Initialize Unicorn ARM64 emulator
        self.uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)

        # Memory Layout
        self.BASE_ADDR = 0x4000000
        self.CODE_SIZE = 200 * 1024 * 1024 # 200MB
        self.STACK_ADDR = 0x7fff0000
        self.STACK_SIZE = 8 * 1024 * 1024 # 8MB
        self.HEAP_ADDR = 0x20000000
        self.HEAP_SIZE = 100 * 1024 * 1024 # 100MB

        self.libraries = {}
        self.symbols = {}
        self.next_lib_addr = self.BASE_ADDR

        if self.verbose:
            log_print("Unicorn", "ARM64 emulator initialized")

    def _setup_memory(self):
        # Map code/data regions
        self.uc.mem_map(self.BASE_ADDR, self.CODE_SIZE, UC_PROT_ALL)

        # Map stack
        self.uc.mem_map(self.STACK_ADDR, self.STACK_SIZE, UC_PROT_READ | UC_PROT_WRITE)
        self.uc.reg_write(UC_ARM64_REG_SP, self.STACK_ADDR + self.STACK_SIZE - 16)

        # Map heap
        self.uc.mem_map(self.HEAP_ADDR, self.HEAP_SIZE, UC_PROT_READ| UC_PROT_WRITE)
        self.heap_ptr = self.HEAP_ADDR

        if self.verbose:
            log_print("Memory", f"Code: 0x{self.BASE_ADDR:x} ({self.CODE_SIZE // (1024 * 1024)}MB)")
            log_print("Memory", f"Stack: 0x{self.STACK_SIZE:x} ({self.STACK_SIZE // (1024 * 1024)}MB)")
            log_print("Memory", f"Heap: 0x{self.HEAP_ADDR:x} ({self.HEAP_SIZE // (1024 * 1024)}MB)")


    def _setup_hooks(self):
        self.uc.hook_add(UC_HOOK_MEM_UNMAPPED, self._hook_interrupt)


    def _hook_interrupt(self, uc, int_num, user_data):
        syscall_num = uc.reg_read(UC_ARM64_REG_X8)
        args = [uc.reg_read(UC_ARM64_REG_X0 + i) for i in range(6)]

        if self.verbose:
            log_print("Syscall", f"#{syscall_num} args={[hex(a) for a in args]}")

        result = self._handle_syscall(syscall_num, args)
        uc.reg_write(UC_ARM64_REG_X0, result & 0xFFFFFFFFFFFFFFFF)

    def _handle_syscall(self, syscall_num, args):
        syscalls = {
            56: self._sys_openat,
            57: self._sys_close,
            63: self._sys_read,
            64: self._sys_write,
            93: self._sys_exit,
            160: self._sys_uname,
            214: self._sys_brk,
            222: self._sys_mmap
        }

        handler = syscalls.get(syscall_num, self._sys_unimplemented)
        return handler(args)

    def _sys_openat(self, args):
        return 3 ### simplified, returns a fake filedescriptor

    def _sys_close(self, args):
        return 0

    def _sys_read(self, args):
        return 0 # simplified, returns '0' (EOF)

    def _sys_write(self, args):
        fd, buf_addr, count = args[0], args[1], args[2]

        try:
            data = self.uc.mem_read(buf_addr, count)

            if fd == 1: # stdout
                sys.stdout.write(data.decode('utf-8', errors='ignore'))
                sys.stdout.flush()
            elif fd == 2: # stderr
                sys.stdout.write(data.decode('utf-8', errors='ignore'))
                sys.stdout.flush()

            return count # num of bytes written

        except Exception as e:
            if self.verbose:
                log_print("Syscall", "write error", f"{e}")
            return -1

    def _sys_exit(self, args):
        exit_code = args[0]
        if self.verbose:
            log_print("Syscall", f"exit({exit_code})")
        self.uc.emu_stop()
        return exit_code

    def _sys_uname(self, args):
        buf_addr = args[0]

        fill_w_null_bytes = b"\x00" * 60

        uname_data = b"Android\x00" + fill_w_null_bytes # sysname
        uname_data += b"project platypus\x00" + fill_w_null_bytes # nodename
        uname_data += b"5.14.1\x00" + fill_w_null_bytes # release
        uname_data += b"#1 SMP\x00" + fill_w_null_bytes # version
        uname_data += b"aarch64\x00" + fill_w_null_bytes # machine

        try:
            self.uc.mem_write(buf_addr, uname_data)
            return 0
        except Exception as e:
            return -1

    def _sys_brk(self, args):
        addr = args[0]

        if addr == 0:
            return self.heap_ptr # Query current break
        else:
            if self.heap_ptr < addr < self.HEAP_ADDR + self.HEAP_SIZE:
                self.heap_ptr = addr
            return self.heap_ptr

    def _sys_mmap(self, args):
        length = args[1]

        result = self.heap_ptr # allocate from heap
        self.heap_ptr += (length + 0xfff) & ~0xfff # page align

        if self.verbose:
            log_print("Syscall", f"mmap -> 0x{result:x}")

        return result

    def _sys_unimplemented(self, args):
        if self.verbose:
            log_print("Syscall", "unimplemented")
        return 0 # Return success by default

    def _hook_mem_invalid(self, uc, access, address, size, value, user_data):
        log_print("ERROR", "invalid memory access")
        print(f"    Address: 0x{address:x}")
        print(f"    Size: {size}")
        print(f"    Access: {access}")
        return False

    def _hook_code(self, uc, address, size, user_data):
        try:
            code = uc.mem_read(address, size)
            log_print("Code", f"0x{address:x}", f"{code.hex()}")
        except Exception as e:
            pass

    def load_elf_library(self, path):
        if self.verbose:
            print(f"\n[Loading] {path}")

        with open(path, "rb") as f:
            elf = ELFFile(f)

            if elf.header["e_machine"] != 'EM_AARCH64': # check lib to make sure it actually is aarch64
                raise ValueError(f"Not an ARM64 binary/library: {elf.header['e_machine']}")

            # Allocate base address
            load_base = self.next_lib_addr
            max_addr = load_base

            # Load library segemnts
            for segment in elf.iter_segments():
                if segment["p_type"] == "PT_LOAD":
                    vaddr = load_base + segment["p_vaddr"]
                    memsz = segment["p_memsz"]
                    filesz = segment["p_filesz"]
                    data = segment.data()

                    if self.verbose:
                        perms = []
                        if segment["p_flags"] & 4: perms.append("R")
                        if segment["p_flags"] & 2: perms.append("W")
                        if segment["p_flags"] & 1: perms.append("X")
                        print(f"    Segment: 0x{vaddr:x} size=0x{memsz:x} perm{''.join(perms)}")

                    # Write data
                    if filesz > 0:
                        try:
                            self.uc.mem_write(vaddr, data)
                        except UcError as e:
                            print(f"    Error writing memory: {e}")

                    max_addr = max(max_addr, vaddr + memsz)

            # Update next lib address
            self.next_lib_addr = (max_addr + 0xfffff) & ~0xfffff # align to 1MB

            # Parse symbols
            symtab = elf.get_section_by_name(".symtab") or elf.get_section_by_name(".dynsym")
            if symtab:
                symbol_count = 0
                for symbol in symtab.iter_symbols():
                    if symbol["st_value"] != 0 and symbol.name:
                        sym_addr = load_base + symbol["st_value"]
                        self.symbols[symbol.name] = sym_addr
                        symbol_count += 1

                if self.verbose:
                    print(f"    Symbols: {symbol_count} loaded")

            lib_name = os.path.basename(path)
            self.libraries[lib_name] = {
                "base": load_base,
                "size": max_addr - load_base,
                "path": path,
            }

            if self.verbose:
                print(f"    Base: 0x{load_base:x}")
                print(f"    Size: 0x{max_addr-load_base:x}")

            return load_base

    def get_symbol_address(self, name):
        return self.symbols.get(name)

    def call_function(self, func_name, args):
        if func_name not in self.symbols:
            raise ValueError(f"Symbol not found: {func_name}")

        func_addr = self.symbols[func_name]

        if self.verbose:
            print(f"\n[Call] {func_name} @ 0x{func_addr:x}")
            print(f"    Args: {args}")

        for i, arg in enumerate(args[:8]): # Setup arguments in X0-X7
            self.uc.reg_read(UC_ARM64_REG_X0 + i, arg)

        ret_addr = 0xDEADBEEF # Setup return addr
        self.uc.reg_write(UC_ARM64_REG_LR, ret_addr)

        try:
            self.uc.emu_start(func_addr, ret_addr, timeout=10*1000000) # 10 Second timeout
        except UcError as e:
            log_print("ERROR", "Emulation failed", f"{e}")
            try:
                pc = self.uc.reg_read(UC_ARM64_REG_PC)
                print(f"    PC: 0x{pc:x}")
            except:
                pass
            raise

        # Get the return value
        result = self.uc.reg_read(UC_ARM64_REG_X0)
        if self.verbose:
            print(f"    Result: 0x{result:x} ({result}")

        return result

    def read_string(self, addr):
        result = b""
        try:
            while len(result) < 1024: # Max 1KB
                byte = self.uc.mem_read(addr + len(result), 1)
                if byte == b"\x00":
                    break
                result += byte
            return result.decode("utf-8", errors="ignore")
        except:
            return ""


