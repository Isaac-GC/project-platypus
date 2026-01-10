from vm.mock_handler import register_mock


@register_mock
def getClassName(args, state_data):
    # return state_data['current_registers'][0]["class_name"]
    return args[0]["class_name"]

@register_mock
def getMethodName(args, state_data):
    # return state_data['current_registers'][0][0]["method_name"]
    return args[0]["method_name"]