"""Flux d'entrée NEX (stream_in.go). Remplace `crunch.Buffer` par un offset sur des bytes."""
from __future__ import annotations

import struct
from typing import Any, Callable, TYPE_CHECKING

from .errors import NexError
from .nex_types import DataHolder, DateTime

if TYPE_CHECKING:
    from .nex_types import Structure
    from .server import Server


class StreamIn:
    def __init__(self, data: bytes, server: Server | None = None):
        self.server = server
        self._data = bytes(data)
        self._offset = 0

    # -- bas niveau ---------------------------------------------------------
    def to_bytes(self) -> bytes:
        """Équivalent de `Bytes()` : l'intégralité des données du flux."""
        return self._data

    def byte_offset(self) -> int:
        return self._offset

    def byte_capacity(self) -> int:
        return len(self._data)

    def remaining(self) -> int:
        return len(self._data) - self._offset

    def seek_byte(self, offset: int, relative: bool = False) -> None:
        self._offset = (self._offset + offset) if relative else offset

    def read_bytes_next(self, n: int) -> bytes:
        if n < 0 or self.remaining() < n:
            raise NexError("[StreamIn] Not enough data left in stream")
        chunk = self._data[self._offset:self._offset + n]
        self._offset += n
        return chunk

    # -- types primitifs ----------------------------------------------------
    def read_bool(self) -> bool:
        return self.read_uint8() == 1

    def read_uint8(self) -> int:
        return self.read_bytes_next(1)[0]

    def read_uint16le(self) -> int:
        return struct.unpack("<H", self.read_bytes_next(2))[0]

    def read_uint32le(self) -> int:
        return struct.unpack("<I", self.read_bytes_next(4))[0]

    def read_int32le(self) -> int:
        return struct.unpack("<i", self.read_bytes_next(4))[0]

    def read_uint64le(self) -> int:
        return struct.unpack("<Q", self.read_bytes_next(8))[0]

    # -- types NEX ----------------------------------------------------------
    def read_string(self) -> str:
        length = self.read_uint16le()

        if self.remaining() < length:
            raise NexError("[StreamIn] Nex string length longer than data size")

        string_data = self.read_bytes_next(length)
        return string_data.decode("utf-8", errors="replace").rstrip("\x00")

    def read_buffer(self) -> bytes:
        length = self.read_uint32le()

        if self.remaining() < length:
            raise NexError("[StreamIn] Nex buffer length longer than data size")

        return self.read_bytes_next(length)

    def read_qbuffer(self) -> bytes:
        length = self.read_uint16le()

        if self.remaining() < length:
            raise NexError("[StreamIn] Nex qBuffer length longer than data size")

        return self.read_bytes_next(length)

    def read_structure(self, structure: Structure) -> Structure:
        for cls in structure.hierarchy():
            try:
                self.read_structure(cls)
            except NexError as e:
                raise NexError("[ReadStructure] " + str(e)) from e

        if self.server.nex_version >= 30500:
            # on ignore le nouvel en-tête de structure, les données ne nous servent pas
            self.read_uint8()     # structure header version
            self.read_uint32le()  # structure content length

        try:
            structure.extract_from_stream(self)
        except NexError as e:
            raise NexError("[ReadStructure] " + str(e)) from e

        return structure

    def read_variant(self) -> Any:
        """Lit un Variant (7 types possibles)."""
        kind = self.read_uint8()

        if kind == 0:  # null
            return None
        if kind == 1:  # sint64
            return struct.unpack("<q", self.read_bytes_next(8))[0]
        if kind == 2:  # double
            # NOTE (correction vs Go) : Go fait float64(uint64) (conversion de la
            # valeur) ; on décode ici le vrai IEEE-754 little-endian.
            return struct.unpack("<d", self.read_bytes_next(8))[0]
        if kind == 3:  # bool
            return self.read_uint8() == 1
        if kind == 4:  # string
            return self.read_string()
        if kind == 5:  # datetime
            return DateTime(self.read_uint64le())
        if kind == 6:  # uint64
            return self.read_uint64le()

        return None

    def read_map(self, key_function: Callable[[], Any], value_function: Callable[[], Any]) -> dict:
        """Lit une Map NEX.

        En Go, les types de clé/valeur étaient détectés via `interface{}` (TODO
        "make this not suck"). Ici on passe simplement les méthodes de lecture :
        ``stream.read_map(stream.read_string, stream.read_variant)``.
        """
        length = self.read_uint32le()
        new_map = {}

        for _ in range(length):
            key = key_function()
            value = value_function()
            new_map[key] = value

        return new_map

    def read_datetime(self) -> DateTime:
        return DateTime(self.read_uint64le())

    def read_data_holder(self) -> DataHolder:
        data_holder = DataHolder()
        data_holder.extract_from_stream(self)
        return data_holder

    # -- listes -------------------------------------------------------------
    def _read_list(self, read_item: Callable[[], Any]) -> list:
        length = self.read_uint32le()
        return [read_item() for _ in range(length)]

    def read_list_uint8(self) -> list[int]:
        return self._read_list(self.read_uint8)

    def read_list_uint16le(self) -> list[int]:
        return self._read_list(self.read_uint16le)

    def read_list_uint32le(self) -> list[int]:
        return self._read_list(self.read_uint32le)

    def read_list_int32le(self) -> list[int]:
        return self._read_list(self.read_int32le)

    def read_list_uint64le(self) -> list[int]:
        return self._read_list(self.read_uint64le)

    def read_list_string(self) -> list[str]:
        return self._read_list(self.read_string)

    def read_list_qbuffer(self) -> list[bytes]:
        return self._read_list(self.read_qbuffer)
