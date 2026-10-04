from __future__ import annotations

from .errors import ERROR_MASK, NexError
from .stream_in import StreamIn
from .stream_out import StreamOut


class RMCRequest:
    def __init__(self):
        self.protocol_id = 0
        self.custom_id = 0
        self.call_id = 0
        self.method_id = 0
        self.parameters = b""

    def from_bytes(self, data: bytes) -> None:
        if len(data) < 13:
            raise NexError("[RMC] Data size less than minimum")

        stream = StreamIn(data, None)

        size = stream.read_uint32le()

        if size != len(data) - 4:
            raise NexError("[RMC] Data size does not match")

        protocol_id = stream.read_uint8() ^ 0x80
        if protocol_id == 0x7F:
            self.custom_id = stream.read_uint16le()
        call_id = stream.read_uint32le()
        method_id = stream.read_uint32le()
        parameters = data[stream.byte_offset():]

        self.protocol_id = protocol_id
        self.call_id = call_id
        self.method_id = method_id
        self.parameters = parameters

    def to_bytes(self) -> bytes:
        body = StreamOut(None)

        body.write_uint8(self.protocol_id | 0x80)
        if self.protocol_id == 0x7F:
            body.write_uint16le(self.custom_id)

        body.write_uint32le(self.call_id)
        body.write_uint32le(self.method_id)

        if self.parameters:
            body.write_bytes_next(self.parameters)

        data = StreamOut(None)
        data.write_buffer(body.to_bytes())

        return data.to_bytes()


class RMCResponse:
    def __init__(self, protocol_id: int, call_id: int):
        self.protocol_id = protocol_id
        self.custom_id = 0
        self.success = 0
        self.call_id = call_id
        self.method_id = 0
        self.data = b""
        self.error_code = 0

    def set_success(self, method_id: int, data: bytes) -> None:
        self.success = 1
        self.method_id = method_id
        self.data = data

    def set_error(self, error_code: int) -> None:
        if error_code & ERROR_MASK == 0:
            error_code = error_code | ERROR_MASK

        self.success = 0
        self.error_code = error_code

    def to_bytes(self) -> bytes:
        body = StreamOut(None)

        body.write_uint8(self.protocol_id)
        if self.protocol_id == 0x7F:
            body.write_uint16le(self.custom_id)
        body.write_uint8(self.success)

        if self.success == 1:
            body.write_uint32le(self.call_id)
            body.write_uint32le(self.method_id | 0x8000)

            if self.data:
                body.write_bytes_next(self.data)
        else:
            body.write_uint32le(self.error_code)
            body.write_uint32le(self.call_id)

        data = StreamOut(None)
        data.write_buffer(body.to_bytes())

        return data.to_bytes()
