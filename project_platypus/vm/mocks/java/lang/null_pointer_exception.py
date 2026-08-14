from vm.mock_handler import register_mock


@register_mock
def _0init0(args, state_data):
    curr_registers = state_data['current_registers']
    params = state_data['raw_param_values']

    if args and args[0]:
        print(f"NullPointerException encountered: {curr_registers[params[1]]}")
    else:
        print("NullPointerException encountered")