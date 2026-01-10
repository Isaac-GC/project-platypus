import inspect

from vm.mock_handler import register_mock


@register_mock
def forName(args, state_data):
    return args[0]

@register_mock
def getName(args, state_data):
    # curr_frame = inspect.currentframe()
    # calframe = inspect.getouterframes(curr_frame, 3)
    # print(f"Caller {calframe[1][3]}")
    return state_data['current_registers'][1]

@register_mock
def getMethod(args, state_data):
    return [args[0], args[1]]