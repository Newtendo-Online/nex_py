"""Utilitaires partagés (md5.go, sum.go, init.go)."""
from __future__ import annotations

import hashlib
import logging

# Équivalent du `logger` plogger de Go
logger = logging.getLogger("nex")


def md5_hash(data: bytes) -> bytes:
    """Retourne le hash MD5 de l'entrée."""
    return hashlib.md5(data).digest()


def sum_bytes(data: bytes) -> int:
    """Somme des octets (fonction `sum` de sum.go)."""
    return sum(data)
