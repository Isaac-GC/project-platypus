from vm.mock_handler import register_mock, MOCKS_REGISTRY, METHOD_VM_NEEDED


@register_mock
def invoke(args, state_data, vm):

    # TODO: Logic is copied from legacy code, update it to allow for better error handling
    try:
        t_class_name = f"L{args[0][0].replace('.','/')};"
    except:
        t_class_name = "None"


    mthd = None
    t_method_name = args[0][1]
    if t_class_name in vm.lookup_map:
        if t_method_name in vm.lookup_map[t_class_name]:
            mthd = vm.lookup_map[t_class_name][t_method_name]

    if mthd:
        fqcn = f"{mthd.class_name.replace('/','_').replace(';', '')}_{mthd.method_name.replace('<','0').replace('>','0')}"
        func = MOCKS_REGISTRY.get('fqcn', None)

        if func:
            try:
                if fqcn in METHOD_VM_NEEDED:
                    func(args[1:], state_data, vm)
                else:
                    func(args[1:], state_data)

            except Exception as ex:
                pass # TODO: FIX THIS!!!!

        elif mthd.class_name == "Landroid/view/Display":
            return 0

        else:
            if any([x in mthd.method_name for x in ["Int", "Long", "Float"]]) and "get" in mthd.method_name:
                return 0

            if "String" in mthd.method_name and "get" in mthd.method_name and len(mthd.method_name) > 9:
                return "None"

            if "Array" in mthd.method_name and "get" in mthd.method_name:
                return []

    return None