from vm.mock_handler import register_mock


@register_mock
def _0init0(args, state_data): # <init> functions must always replace '<'/'>' with '0' and have '_' out front
    value = ''

    if len(args) > 1:
        match args[1]:
            case list(): value = ''.join(chr(i) for i in args[1])
            case str():  value = args[1]

    args[0] = value


@register_mock
def append(args, state_data):
    curr_registers = state_data['current_registers']
    param_vals = state_data['raw_param_values']
    try:
        # args[0] = f"{str(args[0])}{chr[args[1]]}"
        curr_registers[param_vals[0]] += curr_registers[param_vals[1]]
    except TypeError as te:
        try:
            curr_registers[param_vals[0]] += curr_registers[param_vals[1]].decode('utf-8')
            # args[0] = f"{str(args[0])}{args[1].decode('utf-8')}"
        except AttributeError as ae:
            curr_registers[param_vals[0]] += str(curr_registers[param_vals[1]])
            # args[0] = f"{str(args[0])}{str(args[1])}"

    return args[0]


@register_mock
def length(args, state_data):
    value = 0
    try:
        value = len(args[0])
    except Exception as e:
        pass

    return value


@register_mock
def toString(args, state_data):
    if args[0] == '':
        return args[1]
    else:
        return args[0]