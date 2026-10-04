"""Flux de sortie NEX (stream_out.go). Remplace `crunch.Buffer` par un bytearray."""
from __future__ import annotations

import struct
from typing import Callable, Iterable, TYPE_CHECKING

if TYPE_CHECKING:
    from .nex_types import DataHolder, Result, Structure
    from .server import Server


class StreamOut:
    def __init__(self, server: Server | None = None):
        self.server = server
        self._buf = bytearray()

    # -- bas niveau ---------------------------------------------------------
    def to_bytes(self) -> bytes:
        """Équivalent de `Bytes()` : tout le contenu écrit jusqu'ici."""
        return bytes(self._buf)

    def grow(self, size: int) -> None:
        """No-op : le bytearray grandit tout seul (gardé pour la parité avec Go)."""

    def write_bytes_next(self, data: bytes) -> None:
        self._buf += data

    # -- types primitifs ----------------------------------------------------
    def write_bool(self, b: bool) -> None:
        self._buf.append(1 if b else 0)

    def write_uint8(self, v: int) -> None:
        self._buf.append(v & 0xFF)

    def write_uint16le(self, v: int) -> None:
        self._buf += struct.pack("<H", v & 0xFFFF)

    def write_uint32le(self, v: int) -> None:
        self._buf += struct.pack("<I", v & 0xFFFFFFFF)

    def write_int32le(self, v: int) -> None:
        self._buf += struct.pack("<I", v & 0xFFFFFFFF)

    def write_uint64le(self, v: int) -> None:
        self._buf += struct.pack("<Q", v & 0xFFFFFFFFFFFFFFFF)

    def write_int64le(self, v: int) -> None:
        self._buf += struct.pack("<Q", v & 0xFFFFFFFFFFFFFFFF)

    # -- types NEX ----------------------------------------------------------
    def write_string(self, s: str) -> None:
        """String NEX : uint16 (longueur incluant le \\0 final) + octets + \\0."""
        data = (s + "\x00").encode("utf-8")
        self.write_uint16le(len(data))
        self._buf += data

    def write_buffer(self, data: bytes) -> None:
        """Buffer NEX : uint32 (longueur) + octets."""
        self.write_uint32le(len(data))
        if len(data) > 0:
            self._buf += data

    def write_qbuffer(self, data: bytes) -> None:
        """qBuffer NEX : uint16 (longueur) + octets."""
        self.write_uint16le(len(data))
        if len(data) > 0:
            self._buf += data

    def write_result(self, result: Result) -> None:
        self.write_uint32le(result.code)

    def write_structure(self, structure: Structure) -> None:
        content = structure.to_bytes(StreamOut(self.server))

        if self.server.nex_version >= 30500:
            self.write_uint8(1)  # version
            self.write_uint32le(len(content))

        self._buf += content

    def write_data_holder(self, dataholder: DataHolder) -> None:
        # NOTE (correction vs Go) : la version Go passe `stream` lui-même à
        # DataHolder.Bytes(), ce qui écrit les données puis les ré-ajoute une
        # seconde fois. On passe ici un flux neuf, comme pour WriteStructure.
        content = dataholder.to_bytes(StreamOut(self.server))
        self._buf += content

    # -- listes -------------------------------------------------------------
    def _write_list(self, items: Iterable, write_item: Callable) -> None:
        items = list(items)
        self.write_uint32le(len(items))
        for item in items:
            write_item(item)

    def write_list_uint8(self, items: Iterable[int]) -> None:
        self._write_list(items, self.write_uint8)

    def write_list_uint16le(self, items: Iterable[int]) -> None:
        self._write_list(items, self.write_uint16le)

    def write_list_uint32le(self, items: Iterable[int]) -> None:
        self._write_list(items, self.write_uint32le)

    def write_list_uint64le(self, items: Iterable[int]) -> None:
        self._write_list(items, self.write_uint64le)

    def write_list_int64le(self, items: Iterable[int]) -> None:
        self._write_list(items, self.write_int64le)

    def write_list_structure(self, structures: Iterable[Structure]) -> None:
        self._write_list(structures, self.write_structure)

    def write_list_string(self, strings: Iterable[str]) -> None:
        self._write_list(strings, self.write_string)

    def write_list_qbuffer(self, buffers: Iterable[bytes]) -> None:
        self._write_list(buffers, self.write_qbuffer)

    def write_list_result(self, results: Iterable[Result]) -> None:
        self._write_list(results, self.write_result)
