from vm.mock_handler import register_mock


@register_mock
def _0init0(args, state_data):
    match args[1]:
        case list(): args[0] = ''.join(chr(i) for i in args[1])
        case str():  args[0] = args[1]


@register_mock
def toString(args, state_data):
    return args[0]