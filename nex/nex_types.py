from __future__ import annotations

import datetime as _dt
from typing import TYPE_CHECKING

from .errors import ERROR_MASK, NexError
from .stream_out import StreamOut

if TYPE_CHECKING:
    from .stream_in import StreamIn


class Structure:
    def hierarchy(self) -> list[Structure]:
        return []

    def extract_from_stream(self, stream: StreamIn) -> None:
        raise NotImplementedError

    def to_bytes(self, stream: StreamOut) -> bytes:
        raise NotImplementedError


class Data(Structure):
    def extract_from_stream(self, stream: StreamIn) -> None:
        stream.seek_byte(0, True)

    def to_bytes(self, stream: StreamOut) -> bytes:
        return stream.to_bytes()


_data_holder_known_objects: dict[str, Structure] = {}


def register_data_holder_type(structure: Structure) -> None:
    _data_holder_known_objects[type(structure).__name__] = structure


class DataHolder:
    def __init__(self):
        self.type_name = ""
        self.length1 = 0
        self.length2 = 0
        self.object_data: Structure | None = None

    def extract_from_stream(self, stream: StreamIn) -> None:
        self.type_name = stream.read_string()
        self.length1 = stream.read_uint32le()
        self.length2 = stream.read_uint32le()

        known = _data_holder_known_objects.get(self.type_name)
        if known is None:
            raise NexError(f"[DataHolder] Unknown structure type {self.type_name!r}")

        new_object_instance = type(known)()
        self.object_data = stream.read_structure(new_object_instance)

    def to_bytes(self, stream: StreamOut) -> bytes:
        content = self.object_data.to_bytes(StreamOut(stream.server))

        stream.write_string(self.type_name)
        stream.write_uint32le(len(content) + 4)
        stream.write_buffer(content)

        return stream.to_bytes()


class RVConnectionData(Structure):
    def __init__(self):
        self.station_url = ""
        self.special_protocols = b""
        self.station_url_special_protocols = ""
        self.time = 0

    def to_bytes(self, stream: StreamOut) -> bytes:
        stream.write_string(self.station_url)
        stream.write_uint32le(0)  # toujours 0
        stream.write_string(self.station_url_special_protocols)
        stream.write_uint64le(self.time)

        return stream.to_bytes()


class DateTime:
    def __init__(self, value: int = 0):
        self.value = value

    def make(self, year: int, month: int, day: int, hour: int, minute: int, second: int) -> int:
        self.value = second | (minute << 6) | (hour << 12) | (day << 17) | (month << 22) | (year << 26)
        return self.value

    def from_timestamp(self, timestamp: _dt.datetime) -> int:
        return self.make(timestamp.year, timestamp.month, timestamp.day,
                         timestamp.hour, timestamp.minute, timestamp.second)

    def now(self) -> int:
        return self.from_timestamp(_dt.datetime.now())

    def __repr__(self) -> str:
        return f"DateTime({self.value})"


class StationURL:
    _FIELDS = (
        ("address", "address"), ("port", "port"), ("stream", "stream"), ("sid", "sid"),
        ("CID", "cid"), ("PID", "pid"), ("type", "transport_type"), ("RVCID", "rvcid"),
        ("natm", "natm"), ("natf", "natf"), ("upnp", "upnp"), ("pmp", "pmp"),
        ("probeinit", "probeinit"), ("PRID", "prid"),
    )

    def __init__(self, string: str = ""):
        self.scheme = ""
        self.address = ""
        self.port = ""
        self.stream = ""
        self.sid = ""
        self.cid = ""
        self.pid = ""
        self.transport_type = ""
        self.rvcid = ""
        self.natm = ""
        self.natf = ""
        self.upnp = ""
        self.pmp = ""
        self.probeinit = ""
        self.prid = ""

        if string != "":
            self.from_string(string)

    def from_string(self, string: str) -> None:
        split = string.split(":/")

        self.scheme = split[0]
        fields = split[1]

        attr_by_name = dict(self._FIELDS)

        for param in fields.split(";"):
            kv = param.split("=")
            if len(kv) < 2:
                continue

            attr = attr_by_name.get(kv[0])
            if attr is not None:
                setattr(self, attr, kv[1])

    def encode_to_string(self) -> str:
        fields = []
        for name, attr in self._FIELDS:
            value = getattr(self, attr)
            if value != "":
                fields.append(f"{name}={value}")

        return self.scheme + ":/" + ";".join(fields)


class Result(Structure):
    def __init__(self, code: int = 0):
        self.code = code & 0xFFFFFFFF

    @classmethod
    def new_success(cls, code: int) -> Result:
        return cls(code & ~ERROR_MASK)

    @classmethod
    def new_error(cls, code: int) -> Result:
        return cls(code | ERROR_MASK)

    def is_success(self) -> bool:
        return self.code & ERROR_MASK == 0

    def is_error(self) -> bool:
        return self.code & ERROR_MASK != 0

    def extract_from_stream(self, stream: StreamIn) -> None:
        self.code = stream.read_uint32le()

    def to_bytes(self, stream: StreamOut) -> bytes:
        stream.write_uint32le(self.code)
        return stream.to_bytes()


class ResultRange(Structure):
    def __init__(self):
        self.offset = 0
        self.length = 0

    def extract_from_stream(self, stream: StreamIn) -> None:
        self.offset = stream.read_uint32le()
        self.length = stream.read_uint32le()
