from typing import Optional

from codegen.java.analysis import AnalysisConfig


class JavaDecompiler:
    def __init__(self, method, config: Optional[AnalysisConfig] = None):
        self.method = method
        self.config = config or AnalysisConfig()
        self.cfg    = CFGBu