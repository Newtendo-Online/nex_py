from __future__ import annotations


class Counter:
    """Compteur incrémental (uint32, avec retour à zéro comme en Go)."""

    def __init__(self, start: int = 0):
        self.value = start & 0xFFFFFFFF

    def increment(self) -> int:
        """Incrémente de 1 et retourne la nouvelle valeur."""
        self.value = (self.value + 1) & 0xFFFFFFFF
        return self.value
