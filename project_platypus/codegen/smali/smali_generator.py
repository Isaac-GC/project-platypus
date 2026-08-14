# Class is intended to format code in a "normal" type-ish way
#   If code can't be formatted properly, it will error out and just format the raw instructions
#
# Intention is through best effort and additional logic will be implemented to hopefully deobfuscate
# and/or identify unused/dead code
#
# Kudos to JADX as it was used heavily for reference in building the smali code/flow
import logging

from dex.access_flags import parse_method_access_flags
from dex.clazz import Clazz
from dex.helpers import sign_extend
from dex.method import Method
from vm.utils import LogHandler

handler = LogHandler()
log = logging.getLogger(__name__)
log.addHandler(handler)
log.setLevel(logging.INFO)

class SmaliCodeGen:
    def __init__(self, method: Method):
        self.method = method
        self._label_map: dict[int, list[str]] = {}
        self._build_labels()

    def _build_labels(self):
        for instr in self.method.instructions:
            op = instr.opcode

            if 0x28 <= op <= 0x2a: # Goto
                target = instr.codepoint + sign_extend(instr.vA, {0x28: 8, 0x29: 16, 0x2a: 32}[op])
                self._add_label(target, f":goto_{target:x}")

            elif 0x32 <= op <= 0x37: # If/Conditional
                target = instr.codepoint + sign_extend(instr.vC, 16)
                self._add_label(target, f":cond_{target:x}")

            elif 0x38 <= op <= 0x3d:
                target = instr.codepoint + sign_extend(instr.vB, 16)
                self._add_label(target, f":cond_{target:x}")

            elif op in [0x2b, 0x2c]:
                kind = "pswitch" if op == 0x2b else "sswitch"
                for rel in instr.switch_table.values():
                    target = instr.codepoint + rel
                    self._add_label(target, f":{kind}_{target:x}")

            elif op == 0x26:
                target = instr.codepoint + sign_extend(instr.vB, 32)
                self._add_label(target, f":array_{target:x}")

        for try_item in self.method.tries:
            start = try_item.start_addr
            end   = start + try_item.insn_count
            self._add_label(start, f":try_start_{start:x}")
            self._add_label(end, f":try_end_{start:x}")


    def _add_label(self, codepoint: int, label: str):
        if label not in self._label_map.get(codepoint, []):
            self._label_map.setdefault(codepoint, []).append(label)

    def _format_register(self, register: int) -> str:
        if register is None:
            return ""

        param_start = self.method.registers_size - self.method.ins_size
        if register >= param_start:
            return f"p{register - param_start}"
        return f"v{register}"

    def _format_instruction(self, instruction) -> str:
        op = instruction.opcode
        r = self._format_register

        if op == 0x28:
            target = instruction.codepoint + sign_extend(instruction.vA, 8)
            return f"goto :goto_{target:x}"

        if op == 0x29:
            target = instruction.codepoint + sign_extend(instruction.vA, 16)
            return f"goto/16 :goto_{target:x}"

        if op == 0x2a:
            target = instruction.codepoint + sign_extend(instruction.vA, 32)
            return f"goto/32 :goto_{target:x}"

        if 0x32 <= op <= 0x37:
            target = instruction.codepoint + sign_extend(instruction.vC, 16)
            return f"{instruction.prefix} {r(instruction.vA)}, {r(instruction.vB)}, :cond_{target:x}"

        if 0x38 <= op <= 0x3d:
            target = instruction.codepoint + sign_extend(instruction.vB, 16)
            return f"{instruction.prefix} {r(instruction.vA)}, :cond_{target:x}"

        if op in [0x2b, 0x2c]:
            target = instruction.codepoint + instruction.vB
            kind = "packed-switch" if op == 0x2b else "sparse-switch"
            label = f":{'p' if op == 0x2b else 's'}switch_{target:x}"
            return f"{kind} v{r(instruction.vA)}, {label}"

        if op == 0x26:
            target = instruction.codepoint + sign_extend(instruction.vB, 32)
            return f"fill-array-data {r(instruction.vA)}, :array_{target:x}"

        if 0x6e <= op <= 0x72:
            log.debug(
                f"invoke vA={instruction.vA} vB={instruction.vB} "
                f"vC={instruction.vC} vD={instruction.vD} vE={instruction.vE} "
                f"vF={instruction.vF} vG={instruction.vG}"
            )
            all_regs = [instruction.vC, instruction.vD, instruction.vE, instruction.vF, instruction.vG]
            args = ", ".join(r(v) for v in all_regs[:instruction.vA] if v is not None)
            ref = self.method.dex.dex.method_ids[instruction.vB]
            ref_str = f"{ref.class_name}->{ref.method_name}{ref.proto_desc}"
            log.debug(f"invoke vA={instruction.vA} regs={all_regs} args={args!r}")
            return f"{instruction.prefix} {{{args}}}, {ref_str}"

        if 0x74 <= op <= 0x78:
            end_reg = instruction.vC + instruction.vA - 1
            ref = self.method.dex.dex.method_ids[instruction.vB]
            ref_str = f"{ref.class_name}->{ref.method_name}{ref.proto_desc}"
            return f"{instruction.prefix} {{v{r(instruction.vC)} .. v{r(end_reg)}}}, {ref_str}"

        if 0x52 <= op <= 0x5f:
            field = self.method.dex.dex.field_ids[instruction.vC]
            field_ref = f"{field.class_name}->{field.field_name}:{field.type_name}"
            return f"{instruction.prefix} {r(instruction.vA)}, {r(instruction.vB)}, {field_ref}"

        if 0x60 <= op <= 0x6d:
            field = self.method.dex.dex.field_ids[instruction.vB]
            field_ref = f"{field.class_name}->{field.field_name}:{field.type_name}"
            return f"{instruction.prefix} {r(instruction.vA)}, {field_ref}"


        return instruction.instruction_str

    def _format_switch_tables(self) -> list[str]:
        lines = []
        for instruction in self.method.instructions:
            if instruction.opcode not in [0x2b, 0x2c]:
                continue
            kind = "pswitch" if instruction.opcode == 0x2b else "sswitch"
            target = instruction.codepoint + sign_extend(instruction.vB, 32)
            lines.append("")
            lines.append(f"\t:{kind}-data_{target:x}")
            for key, rel in instruction.switch_table.items():
                abs_target = instruction.codepoint + rel
                lines.append(f"\t\t{key:#x}_{abs_target:x}")
            lines.append(f"\t:{kind}-data-end_{target:x}")
        return lines

    def _format_array_payloads(self) -> list[str]:
        lines = []
        for instr in self.method.instructions:
            if instr.opcode != 0x26:
                continue

            target = instr.codepoint + sign_extend(instr.vB, 32)
            lines.append("")
            lines.append(f"    :array_{target:x}")
            lines.append(f"    .array-data {instr.nop_data.get('element_width', 4)}")
            for value in instr.nop_data.get('data', []):
                lines.append(f"        {value:#x}")
            lines.append("    .end array-data")
        return lines

    def _format_catch_statements(self) -> list[str]:
        lines = []
        for try_item in self.method.tries:
            start = try_item.start_addr
            end   = start + try_item.insn_count
            for handler in self.method.handlers:
                for h in handler.handlers:
                    type_name = h['type_id'].type_name
                    addr = h['addr']
                    lines.append(
                        f"\t.catch {type_name} "
                        f"{{:try_start_{start:x} .. :try_end_{start:x}}}"
                        f":catch_{addr:x}"
                    )
                if handler.catch_all_addr:
                    lines.append(
                        f"\t.catchall "
                        f"{{:try_start_{start:x} .. :try_end_{start:x}}}"
                        f":catch_all_{handler.catch_all_addr:x}"
                    )
        return lines

    def format_all(self) -> str:
        m = self.method
        lines = []

        if not isinstance(m, Method):
            log.error(f"format_all: expected Method, got {type(m)}: {m}")
            return f"; error: unexpected type {type(m)}"

        access_flags = " ".join(f.name.lower() for f in parse_method_access_flags(m.access_flags))

        # access = " ".join(f.name.lower() for f in m.access_flags) if m.access_flags else ""
        log.debug(f"method_name={m.method_name!r} params={m.params!r}")
        lines.append(f".method {access_flags} {m.method_name}{m.params}")
        lines.append(f"\t.registers {m.registers_size}")
        lines.append("")

        for instr in m.instructions:
            for label in self._label_map.get(instr.codepoint, []):
                lines.append(f"\t{label}")
            lines.append(f"\t{self._format_instruction(instr)}\n")

        lines += self._format_catch_statements()
        lines += self._format_switch_tables()
        lines += self._format_array_payloads()
        lines.append(".end method")

        return "\n".join(lines)

class SmaliClassCodeGen:
    def __init__(self, clazz: Clazz):
        self.clazz = clazz

    def format(self) -> str:
        c = self.clazz
        lines = []

        access = self._format_flags(c.access_flags)
        lines.append(f".class {access} {c.class_name}")
        lines.append(f".super {c.superclass or 'Ljava/lang/Object;'}")

        if c.source_file:
            lines.append(f".source \"{c.source_file}\"")

        for iface in c.interfaces:
            lines.append(f".implements {iface}")

        if c.static_fields:
            lines.append("")
            lines.append("# static fields")
            for field in c.static_fields:
                lines.append(self._format_field(field))

        if c.instance_fields:
            lines.append("")
            lines.append("# instance fields")
            for field in c.instance_fields:
                lines.append(self._format_field(field))

        for method in c.methods:
            lines.append("")
            lines.append(self._format_method(method))

        return "\n".join(lines)


    def _format_method(self, method: Method) -> str:
        if method.code_offset_val == 0:
            access_flags = self._format_flags(method.access_flags)
            return f".method {access_flags} {method.method_name}({method.params}){method.return_type}\n.end method"
        return SmaliCodeGen(method).format_all()

    def _format_field(self, field) -> str:
        access = self._format_flags(field.access_flags) if hasattr(field, "access_flags") else ""
        name = field.field_name if hasattr(field, 'field_name') else getattr(field, 'name', '?')
        return f".field {access} {name}:{field.type_name}"

    @staticmethod
    def _format_flags(flags) -> str:
        if not flags:
            return ""
        if isinstance(flags, list):
            return " ".join(f.name.lower() for f in flags)

        value = flags.value if hasattr(flags, 'value') else flags

        if not isinstance(value, str):
            return ""
        return ""
