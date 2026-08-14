import re
from collections import namedtuple

Position = namedtuple("Position", ["line", "column"])

class JavaToken(object):
    def __init__(self, value, position=None, javadoc=None):
        self.value = value
        self.position = position
        self.javadoc = javadoc

    def __repr__(self):
        if self.position:
            return f"{self.__class__.__name__} '{self.value}' line {self.position[0]}, position {self.position[1]}"
        else:
            return f"{self.__class__.__name__} '{self.value}'"

    def __str__(self):
        return repr(self)

    def __eq__(self, other):
        raise Exception("Comparing items directly is not allowed")

class EndOfInput(JavaToken):
    pass

class Keyword(JavaToken):
    VALUES = {
        "abstract", "assert",
        "boolean", "break", "byte",
        "case", "catch", "char", "class", "const", "continue",
        "default", "do", "double",
        "else", "enum", "extends",
        "final", "finally", "float", "for",
        "goto",
        "if", "implements", "import", "instanceof", "int", "interface",
        "long",
        "native", "new",
        "package", "private", "protected", "public",
        "return",
        "short", "static", "strictfp", "super", "switch", "synchronized",
        "this", "throw", "throws", "transient", "try",
        "void", "volatile",
        "while",
    }

class Modifier(Keyword):
    VALUES = {
        "abstract",
        "default",
        "final",
        "native",
        "private", "protected", "public",
        "static", "strictfp",
        "synchronized",
        "transient",
        "volatile",
    }

class BasicType(Keyword):
    VALUES = {
        "boolean", "byte",
        "char",
        "double",
        "float",
        "int",
        "long",
        "short",
    }

class Literal(JavaToken): pass
class Integer(Literal): pass
class DecimalInteger(Literal): pass
class OctalInteger(Integer): pass
class BinaryInteger(Integer): pass
class HexInteger(Integer): pass
class FloatingPoint(Literal): pass
class DecimalFloatingPoint(Literal): pass
class HexFloatingPoint(Literal): pass

class Boolean(Literal): VALUES = { "true", "false" }
class Character(Literal): pass
class String(Literal): pass
class Null(Literal): pass

class Annotation(JavaToken): pass
class Identifier(JavaToken): pass

class Separator(JavaToken):
    VALUES = { '(', ')', '{', '}', '[', ']', ';', ',', '.' }

class Operator(JavaToken):
    MAX_LEN = 4
    VALUES = {
        ">>>=", ">>=", "<<=",
        "%=", "^=", "|=", "&=", "/=", "*=", "-=", "+=", "!=",
        ">=", "<=", "==",
        "<<", "--", "++", "||", "&&",
        "%", "^", "|", "&", "/", "*", "-", "+", ":", "?", "~", "!",
        "<", ">", "=", "...", "->", "::"
    }

    INFIX = {
        "||", "&&", "==", "!=", ">=", "<=", ">>", "<<", ">>>",
        "|", "^", "<", ">", "+", "-", "*", "/", "%"
    }

    PREFIX = {
        "++", "--",
        "!", "~", "+", "-"
    }

    POSTFIX = {
        "++", "--"
    }

    ASSIGNMENT = {
        "=",
        "+=", "-=", "*=", "/=", "&=", "|=", "^=", "%=",
        "<<=", ">>=", ">>>="
    }

    LAMBDA = { "->" }

    METHOD_REFERENCE = { "::" }

    def is_infix(self):
        return self.value in self.INFIX

    def is_prefix(self):
        return self.value in self.PREFIX

    def is_suffix(self):
        return self.value in self.POSTFIX

    def is_assignment(self):
        return self.value in self.ASSIGNMENT

class JavaTokenizer(object):
    IDENT_START_CATEGORIES = {
        "Lu", "Ll", "Lt", "Lm", "Lo",
        "Nl",
        "Pc",
        "Sc"
    }

    IDENT_PART_CATEGORIES = {
        "Lu", "Ll", "Lt", "Lm", "Lo",
        "Mc", "Mn",
        "Nd", "Nl",
        "Pc",
        "Sc"
    }

    def __init__(self, data, ignore_errors=False):
        self.data = data
        self.ignore_errors = ignore_errors
        self.errors = []

        self.i = 0
        self.j = 0

        self.current_line = 1
        self.start_of_line = -1

        self.operators = [set()  for _ in range(0, Operator.MAX_LEN)]

        for v in Operator.VALUES:
            self.operators[len(v) - 1].add(v)

        self.whitespace_consumer = re.compile(r'\S')
        self.javadoc = None

    def reset(self):
        self.i = 0
        self.j = 0

    def consume_whitespace(self):
        match = self.whitespace_consumer.search(self.data, self.i + 1)

        if not match:
            self.i = self.length

        i = match.start()

        start_of_line = self.data.rfind('\n', self.i, i)
        if start_of_line != -1:
            self.start_of_line = start_of_line
            self.current_line += self.data.count('\n', self.i, i)

        self.i = i

    def read_string(self):
        delim = self.data[self.i]

        state = 0
        j = self.i + 1
        length = self.length

        while True:
            if j >= length:
                self.error("Unterminated character/string literal")
                break

