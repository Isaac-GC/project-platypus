from vm.mock_handler import register_mock


@register_mock
def forName(args, state_data):
    return args[0]

@register_mock
def getName(args, state_data):
    return args[0]

@register_mock
def getMethod(args, state_data):
    return [args[0], args[1]]