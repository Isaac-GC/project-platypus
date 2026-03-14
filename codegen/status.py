from dataclasses import dataclass
from typing import List


@dataclass
class Status:
    success: bool

@dataclass
class MultiStatus:
    num_failed: int
    num_success: int
    status_list: List[Status]

    threshold: int
    use_threshold: bool = False

    def threshold_exceeded(self) -> bool:
        return self.num_failed >= self.threshold

