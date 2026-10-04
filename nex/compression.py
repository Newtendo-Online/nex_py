from __future__ import annotations


class DummyCompression:
    """Aucune compression."""

    def compress(self, data: bytes) -> bytes:
        return data

    def decompress(self, data: bytes) -> bytes:
        return data


class ZLibCompression:
    """Compression ZLib (comme en Go : pas encore implémentée, renvoie les données telles quelles)."""

    def compress(self, data: bytes) -> bytes:
        return data

    def decompress(self, data: bytes) -> bytes:
        return data
