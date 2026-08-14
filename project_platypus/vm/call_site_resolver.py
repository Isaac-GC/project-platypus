import logging
from enum import Enum

from vm.utils import LogHandler

handler = LogHandler()
log = logging.getLogger(__name__)
log.addHandler(handler)
log.setLevel(logging.INFO)

class MethodHandleType(Enum):
    STATIC_PUT          = 0x00
    STATIC_GET          = 0x01
    INSTANCE_PUT        = 0x02
    INSTANCE_GET        = 0x03
    INVOKE_STATIC       = 0x04
    INVOKE_INSTANCE     = 0x05
    INVOKE_DIRECT       = 0x06
    INVOKE_INTERFACE    = 0x07
    INVOKE_CONSTRUCTOR  = 0x08

class CallSiteResolver:
    def __init__(self, memory):
        self.memory = memory

    def resolve(self, call_site_idx, runtime_args):
        memory = self.memory

        if memory.call_site_cache.is_resolved(call_site_idx):
            target_handle = memory.call_site_cache.get(call_site_idx)
            return self._invoke_handle(target_handle, runtime_args)

        try:
            call_site = memory.dex.dex.call_site_ids[call_site_idx]
            elements  = call_site.value
        except (IndexError, AttributeError) as e:
            log.error(f"Couldn't resolve call_site: {call_site_idx}: {e}")
            return None

        if len(elements) < 3:
            log.error(f"call_site[{call_site_idx}] has less than 3 elements :(")
            return None

        bootstrap_handle_idx = elements[0].value
        target_name    = self._resolve_string(elements[1].value)
        target_proto   = self._resolve_proto(elements[2].value)
        static_args    = [self._resolve_element(el) for el in elements[3:]]

        log.debug(
            f"call_site[{call_site_idx}]: "
            f"bootstrap=method_handle@{bootstrap_handle_idx} "
            f"name={target_name} proto={target_proto} "
            f"static_args={static_args}"
        )

        bootstrap_method = self._resolve_method_handle(bootstrap_handle_idx)
        if bootstrap_method is None:
            log.error(f"Can't resolve bootstrap method handle: {bootstrap_handle_idx}")
            return None

        bootstrap_invoke_args = [None, target_name, target_proto, *static_args]

        call_site_result = self._invoke_bootstrap(bootstrap_method, bootstrap_invoke_args)
        if call_site_result is None:
            log.error(f"Bootstrap method returned NOne for call_site[{call_site_idx}")
            return None

        target_handle = self._get_call_site_target(call_site_idx)
        memory.call_site_cache[call_site_idx] = target_handle

        return self._invoke_handle(target_handle, runtime_args)


    def _resolve_string(self, string_idx):
        return self.memory.dex.dex.string_ids[string_idx].value.raw_data

    def _resolve_proto(self, proto_idx):
        proto = self.memory.dex.dex.protos[proto_idx]
        return proto.shorty_desc

    def _resolve_element(self, element):
        value_type = element.value_type
        value = element.value

        match value_type:
            case 0x17: # string
                return self._resolve_string(value)
            case 0x18: # type
                return self.memory.dex.dex.type_ids[value].type_name
            case 0x19: # field
                return self.memory.dex.dex.field_ids[value]
            case 0x1a: # method
                return self.memory.dex.dex.method_ids[value]
            case 0x1b:
                return self._resolve_method_handle(value)
            case _:
                return value


    def _resolve_method_handle(self, handle_idx):
        handle = self.memory.dex.dex.method_handles[handle_idx]
        handle_type = handle.method_handle_type

        match handle_type:
            case MethodHandleType.INVOKE_STATIC:
                method = self.memory.dex.dex.method_ids[handle.field_or_method_id]
                return {
                    'kind': MethodHandleType.INVOKE_STATIC,
                    'method': method,
                    'idx': handle.field_or_method_id,
                }

            case MethodHandleType.INVOKE_INSTANCE | MethodHandleType.INVOKE_DIRECT:
                method = self.memory.dex.dex.method_ids[handle.field_or_method_id]
                return {
                    'kind': handle_type,
                    'method': method,
                    'idx': handle.field_or_method_id,
                }

            case MethodHandleType.INVOKE_CONSTRUCTOR:
                method = self.memory.dex.dex.method_ids[handle.field_or_method_id]
                return {
                    'kind': MethodHandleType.INVOKE_CONSTRUCTOR,
                    'method': method,
                    'idx': handle.field_or_method_id,
                }

            case MethodHandleType.STATIC_GET | MethodHandleType.STATIC_PUT:
                field = self.memory.dex.dex.field_ids[handle.field_or_method_id]
                return {
                    'kind': handle_type,
                    'field': field,
                    'idx': handle.field_or_method_id
                }

            case MethodHandleType.INSTANCE_GET | MethodHandleType.INSTANCE_PUT:
                field = self.memory.dex.dex.field_ids[handle.field_or_method_id]
                return {
                    'kind': handle_type,
                    'field': field,
                    'idx': handle.field_or_method_id
                }

            case _:
                log.error(f"Unknown method handle type: {handle_type:#x}")
                return None


    def _invoke_bootstrap(self, bootstrap_handle, args):
        if bootstrap_handle is None:
            return None

        kind = bootstrap_handle.get("kind")

        match kind:
            case MethodHandleType.INVOKE_STATIC:
                method_ref = self.memory.dex.lookup_method(bootstrap_handle['idx'])
                if method_ref is None:
                    log.error(f"Bootstrap method not found: {bootstrap_handle['method']}")
                    return None

                result = self.memory.vm.invoke_method(method_ref, args)
                return result

            case _:
                log.error(f"Bootstrap method kind {kind} not supported")
                return None

    def _get_call_site_target(self, call_site_result):
        if isinstance(call_site_result, dict):
            if 'target' in call_site_result:
                return call_site_result['target']
        return call_site_result


    def _invoke_handle(self, handle, args):
        if handle is None:
            return None

        if not isinstance(handle, dict):
            log.error(f"Cannot invoke non-dict handle: {handle}")
            return None

        kind = handle.get("kind")

        match kind:
            case MethodHandleType.INVOKE_STATIC:
                method_ref = self.memory.dex.lookup_method(handle['idx'])
                return self.memory.vm.invoke_method(method_ref, args)

            case MethodHandleType.INVOKE_INSTANCE | MethodHandleType.INVOKE_DIRECT:
                receiver = args[0] if args else None # Unused (currently) TODO!
                method_ref = self.memory.dex.lookup_method(handle['idx'])
                return self.memory.vm.invoke_method(method_ref, args)

            case MethodHandleType.INVOKE_CONSTRUCTOR:
                method_ref = self.memory.dex.lookup_method(handle['idx'])
                return self.memory.vm.invoke_method(method_ref, args)

            case MethodHandleType.STATIC_GET:
                return self.memory.static_fields.get(handle['idx'])

            case MethodHandleType.STATIC_PUT:
                if args:
                    self.memory.static_fields[handle['idx']] = args[0]
                return None

            case MethodHandleType.INSTANCE_GET:
                instance = args[0] if args else None
                return self.memory.instance_fields.get(handle['idx'])

            case MethodHandleType.INSTANCE_PUT:
                if len(args) >= 2:
                    self.memory.instance_fields[handle['idx']] = args[1]
                return None

            case _:
                log.error(f"Unhandled method handle kind: {kind} (Not supported)")
                return None
