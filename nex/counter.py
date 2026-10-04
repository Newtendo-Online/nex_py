from __future__ import annotations


class Counter:
    def __init__(self, start: int = 0):
        self.value = start & 0xFFFFFFFF

    def increment(self) -> int:
        self.value = (self.value + 1) & 0xFFFFFFFF
        return self.value
