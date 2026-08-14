from dex.dexfile import CallSiteCache


class Memory:
    """
    This class implements an execution context for the DVM.
    It includes the execution state information like register values, field values, etc.

    Supports per-instance implementation. Separated out into a separate file
    for per-thread capabilities (will be implemented later)
    """

    def __init__(self, dex=None, fd=None):
        self.last_return = None
        self.last_exception = None

        self.method_instr_values = {}
        self.static_fields = {}
        self.instance_fields = {}

        self.call_site_cache = CallSiteCache()

        self.dex = dex
        self.fd = fd
