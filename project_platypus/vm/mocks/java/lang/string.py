from vm.mock_handler import register_mock

# Android Source
# https://cs.android.com/android/platform/superproject/main/+/main:libcore/ojluni/src/main/java/java/lang/String.java

@register_mock
def _0init0(args, state_data): # <init> functions must always replace '<'/'>' with '0' and have '_' out front
    value = ""
    if args[0] != '':
        try:
            value = bytearray(args[1]).decode('utf-8')
        except ValueError as ve:
            # Probably has negative bytes (which work in java land... just not here), need to remove the sign
            ret = []
            for b in args[1]:
                if b < 0:
                    b += 0xFF + 1
                ret.append(b)
            value = bytearray(ret).decode('utf-8', 'ignore')

    return value

@register_mock
def charAt(args, state_data):
    value = 0
    try:
        value = ord(args[0].decode('utf-8', 'surrogatepass')[args[1]])
    except AttributeError as ae:
        try:
            value = ord(args[0][args[1]])
        except TypeError as te:
            value = args[0][args[1]]

    return value

@register_mock
def split(args, state_data):
    return str(args[0]).split(str(args[1]))


@register_mock
def equals(args, state_data):
    return args[0] == args[1]


@register_mock
def length(args, state_data):
    value = 0

    try:
        value = len(args[0].decode('utf-8'))
    except AttributeError as ae:
        value = len(args[0])

    return value

@register_mock
def hashCode(args, state_data):
    h = 0
    for c in args[0]:
        h = int(((( 31 * h + ord(c) ) ^ 0x80000000) & 0xFFFFFFFF) - 0x80000000)
    return h

@register_mock
def indexOf(args, state_data):
    value = 0

    try:
        value = args[0].find(chr(args[1]))
    except TypeError as te:
        # Sometimes we get substrings, other times we get char codes
        value = str(args[0]).find(str(args[1]))
    except Exception as ex:
        value = 0

    return value


@register_mock
def valueOf(args, state_data):
    value = 0

    try:
        value = chr(args[0])
    except ValueError:
        value = bytes(bytearray(args[0][args[1]:args[1]+args[2]])).decode('ascii')

    return value

@register_mock
def toLowerCase(args, state_data):
    return args[0].lower()

@register_mock
def toUpperCase(args, state_data):
    return args[0].upper()

@register_mock
def getBytes(args: list[str], state_data):
    value = None
    try:
        value = list(args[0].encode('utf-8'))
    except UnicodeError as ue:
        value = list(args[0])

    return value

@register_mock
def toCharArray(args, state_data):
    return [ ord(c) if type(c) is str else c for c in args[0] ]