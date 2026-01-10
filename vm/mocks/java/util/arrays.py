from vm.mock_handler import register_mock


@register_mock
def copyOfRange(args, state_data):
    curr_registers = state_data['current_registers']
    params = state_data['raw_param_values']

    some_array = curr_registers[params[0]]

    start = curr_registers[params[1]]
    end = curr_registers[params[2]]

    if len(some_array) <= start:
        return some_array[start-1:end-1]
    else:
        return some_array[start:end]
