import unicodedata
from dataclasses import dataclass, field

from codegen.java.analysis import AnalysisConfig

# Unicode handler (to hopefully ensure stuff is displayed correctly)
#  - Includes a BIDI string finder to find hidden string items

# unicode chars that are zero-width... not common, but is seen in stuff like arabic
ZERO_WIDTH = {'\u200b', '\u200c', '\u200d', '\ufeff', '\u00ad'}

# BIDI == Bidirectional override chars
BIDI_OVERRIDE = {'\u202a', '\u202b', '\u202c', '\u202d', '\u202e',
                 '\u2066', '\u2067', '\u2068', '\u2069'}


@dataclass
class UnicodeString:
    raw: str
    codepoint: int
    source: str = 'direct'

    has_unicode:   bool = False
    unicode_chars: list = field(default_factory=list)
    script_categories: set = field(default_factory=set)
    is_suspicious:     bool = False
    display_forms:     dict = field(default_factory=dict)

    def analyze(self):
        self.unicode_chars = [c for c in self.raw if ord(c) > 127]
        self.has_unicode   = len(self.unicode_chars) > 0
        self.script_categories = self._categorize_scripts()
        self.is_suspicious     = self.check_suspicious()
        self.display_forms     = self._build_display_forms()

    def _categorize_scripts(self):
        categories = set()
        for c in self.raw:
            if ord(c) > 127:
                try:
                    name   = unicodedata.name(c)
                    script = name.split()[0] if name else 'UNKNOWN'
                    categories.add(script)
                except (ValueError, TypeError):
                    categories.add('UNKNOWN')
        return categories

    def check_suspicious(self):
        latin_scripts = {'LATIN', 'DIGIT', 'SPACE'}
        non_latin     = self.script_categories - latin_scripts
        has_mixed_script = bool(self.script_categories & latin_scripts) and bool(non_latin)

        has_zero_width = any(c in ZERO_WIDTH for c in self.raw)
        has_bidi = any(c in BIDI_OVERRIDE for c in self.raw)

        return has_mixed_script or has_zero_width or has_bidi

    def _build_display_forms(self):
        forms = {
            'raw': self.raw,
            'escaped': self._to_escaped(),
            'unicode': self._to_unicode_names(),
            'hex': self._to_hex(),
        }

        if self.is_suspicious:
            forms['safe'] = self._to_safe()
        return forms


    def _to_escaped(self):
        result = []
        for c in self.raw:
            if ord(c) > 127:
                result.append(f'\\u{ord(c):04x}')
            else:
                result.append(c)
        return ''.join(result)


    def _to_include(self):
        result = []
        for c in self.raw:
            if ord(c) > 127:
                try:
                    name = unicodedata.name(c, f'U+{ord(c):04X}')
                    result.append(f'[{name}]')
                except ValueError:
                    result.append(f'[U+{ord(c):04X}]')
            else:
                result.append(c)
        return ''.join(result)

    def _to_hex(self):
        return ' '.join(f'{ord(c):04x}' for c in self.raw)

    def _to_safe(self):
        result = []
        for c in self.raw:
            if c in ZERO_WIDTH:
                result.append(f'[ZWS:U+{ord(c):04X}]')
            elif c in BIDI_OVERRIDE:
                result.append(f'[BIDI:U+{ord(c):04X}]')
            else:
                result.append(c)

        return ''.join(result)

    def format(self, config: AnalysisConfig):
        mode = config.unicode_display
        if not self.has_unicode: return f'"{self.raw}"'

        if mode == 'unicode': return f'"{self.raw}"'
        if mode == 'escaped': return f'"{self.display_forms["escaped"]}"'

        escaped = self.display_forms['escaped']
        if self.is_suspicious:
            safe = self.display_forms.get('safe', escaped)
            return f'"{self.raw}" /* SUSPICIOUS: {safe} */'
        return f'"{self.raw}" /* {escaped} */'

class Unicode:

    CHAR_BUILD_PATTERNS = [
        "const/4",
        "const/16",
        "add-int",
        "xor-int",
        "new-array",
        "aput-char",
    ]

    def __init__(self, method, config: AnalysisConfig):
        self.method = method
        self.config = config

    def recover_all(self):
        results = {}
        results.update(self._recover_direct_strings())
        results.update(self._recover_escaped_sequences())
        results.update(self._recover_char_arrays())
        results.update(self._recover_xor_strings())
        return results

    def _recover_direct_strings(self):
        results = {}
        for instr in self.method.instructions:
            if instr.opcode not in (0x1a, 0x1b):
                continue

            try:
                raw = self.method.dex.dex.string_ids[instr.opcode].value.raw_data
                s   = raw.decode('utf8', errors='replace') if isinstance(raw, bytes) else str(raw)

                us = UnicodeString(raw=s, codepoint=instr.codepoint)
                us.analyze()
                results[instr.codepoint] = us

            except (IndexError, AttributeError):
                pass

        return results

    def _recover_escaped_sequences(self):
        results = {}
        for cp, us in self._recover_direct_strings().items():
            if '\\u' in us.raw or '\\U' in us.raw:
                decoded = us.raw.encode('raw_unicode_escape').decode('raw_unicode_escape')
                results[cp] = UnicodeString(raw=decoded, codepoint=us.codepoint, source='escaped')
                results[cp].analyze()

        return results

    # (Hopefully) detect string construction via char arrays
    def _recover_char_arrays(self):
        results = {}
        instrs = self.method.instructions
        i = 0

        while i < len(instrs):
            instr = instrs[i]

            # Check for 'new-array' of char type
            if (instr.opcode == 0x23 and self.is_char_array(instr)):
                chars, end_idx = self._extract_char_sequence(instrs, i)
                if chars:
                    s = ''.join(chr(c) for c in chars if 0 <= c <= 0x10FFFF)
                    us = UnicodeString(raw=s, codepoint=instr.codepoint, source='char_array')
                    us.analyze()
                    results[instr.codepoint] = us
                    i = end_idx
                    continue
            i += 1

        return results


    def _recover_xor_strings(self):
        results  = {}
        instrs   = self.method.instructions
        xor_regs = {}

        for i, instr in enumerate(instrs):
            op = instr.opcode

            if op in (0x97, 0xb7, 0xd7): # xor-int variants
                if instr.vA not in xor_regs:
                    xor_regs[instr.vA] = []

            if op == 0xd7:
                reg = instr.vA
                val = instr.vB

                original = self._trace_register_value(instrs, i, instr.vB)
                if original is not None:
                    decoded_char = original ^ val
                    xor_regs.setdefault(reg, []).append(decoded_char)


        for reg, chars in xor_regs.items():
            if len(chars) >= 2:
                try:
                    s = ''.join(chr(c) for c in chars if 0 <= c <= 0x10FFFF)
                    us = UnicodeString(raw=s, codepoint=0, source='xor_decoded')
                    us.analyze()
                    results[id(chars)] = us
                except (ValueError, OverflowError):
                    pass

        return results

    ## HELPERS
    def _is_char_array(self, instr):
        try:
            type_desc = self.method.dex.dex.type_ids[instr.vC].type_name
            return type_desc == '[C'
        except (IndexError, AttributeError):
            return False

    def _extract_char_sequence(self, instrs, start):
        chars = []
        i = start + 1
        pending_const = None

        while i < len(instrs) and i < start + 100:
            instr = instrs[i]
            op = instr.opcode

            if op in (0x12, 0x13) and instr.vA is not None:
                pending_const = (instr.vA, instr.vB)

            elif op == 0x49:
                if pending_const and pending_const[0] == instr.vA:
                    chars.append(pending_const[1])
                    pending_const = None

            elif op in (0x6e, 0x70):
                return chars, i

            i += 1

        return chars, i


    def _trace_register_value(self, instrs, from_idx, reg):
        for i in range(from_idx - 1, max(0, from_idx - 20), -1):
            instr = instrs[i]
            if instr.vA == reg and instr.opcode in (0x12, 0x13, 0x14):
                return instr.vB
        return None