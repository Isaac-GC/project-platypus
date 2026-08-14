from typing import Optional

from codegen.java.ssa_builder import SSABuilder


class JavaGenerator:
    def __init__(self, method, ssa: SSABuilder):
        self.method = method
        self.ssa    = ssa
        self.indent_level = 1
        self._result_var: Optional[str] = None # tracks pending move-result


    def gen_method(self, ast):
        m     = self.method
        lines = []

        ret_type   = self._return_type()
        params_str = self._format_params()
        access_flags = " ".join(f.name.lower() for f in m.access_flags) if m.access_flags else ""
        lines.append(f"{access_flags} {ret_type} {m.method_name}({params_str}) {{")

        # Local variable declerations
        decls = self._gen_declerations()
        for d in decls:
            lines.append(f"\t{d}")
        if decls:
            lines.append("")

        lines += self._gen_method_body(ast)
        lines.append("}")
        return "\n".join(lines)


    def _gen_method_body(self, ast):
        if isinstance(ast, Seq)


