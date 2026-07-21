from dataclasses import dataclass, field
from typing import Optional

from dex.code_block import BasicBlock


@dataclass
class SequenceNode:
    block: Optional[BasicBlock] = None
    blocks: list = field(default_factory=list)

@dataclass
class IfNode:
    condition: str
    true_body: object
    false_body: Optional[object]
    header: BasicBlock

@dataclass
class WhileNode:
    condition: str
    body:      object
    header:    BasicBlock

@dataclass
class DoWhileNode:
    condition: str
    body:      object

@dataclass
class LoopNode:
    body:   object
    header: BasicBlock

