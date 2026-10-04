from __future__ import annotations

import hashlib
import logging


logger = logging.getLogger("nex")


def md5_hash(data: bytes) -> bytes:
    return hashlib.md5(data).digest()


def sum_bytes(data: bytes) -> int:
    return sum(data)
