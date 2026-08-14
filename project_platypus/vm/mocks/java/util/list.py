from vm.mock_handler import register_mock


@register_mock
def _0init0(args, state_data):
    args[0] = []


@register_mock
def size(args, state_data):
    match args[0]:
        case list(): return len(args[0])
        case _: return 0

