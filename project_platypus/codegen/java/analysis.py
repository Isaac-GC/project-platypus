from dataclasses import dataclass
from enum import Enum, auto


class AnalysisPass(Enum):
    DEAD_CODE        = auto()
    DEOBFUSCATION    = auto()
    UNICODE_RECOVERY = auto()

@dataclass
class AnalysisConfig:
    enable_deobfuscation:    bool = True
    enable_unicode_recovery: bool = True
    enable_dead_code:        bool = True
    dead_code_algorithm:     str  = 'z'
    deobfuscation_level:     int  = 2 # 1 = safe, 2 = aggressive, 3 = speculative
    unicode_display:         str  = 'both'

