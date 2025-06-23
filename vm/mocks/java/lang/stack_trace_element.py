from vm.mock_handler import register_mock


@register_mock
def getClassName(args, state_data):
    return args[0]["class_name"]

@register_mock
def getMethodName(args, state_data):
    return args[0]["method_name"]