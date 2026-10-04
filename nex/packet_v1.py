from __future__ import annotations

import hashlib
import hmac
import struct

from .errors import NexError
from .packet import Packet
from .packet_flags import FLAG_HAS_SIZE, FLAG_MULTI_ACK
from .packet_types import CONNECT_PACKET, DATA_PACKET, SYN_PACKET, VALID_TYPES
from .rmc import RMCRequest
from .stream_in import StreamIn
from .stream_out import StreamOut
from .utils import logger


OPTION_ALL_FUNCTIONS = 0xFFFFFFFF
OPTION_SUPPORTED_FUNCTIONS = 0
OPTION_CONNECTION_SIGNATURE = 1
OPTION_FRAGMENT_ID = 2
OPTION_INITIAL_SEQUENCE_ID = 3
OPTION_MAX_SUBSTREAM_ID = 4


class PacketV1(Packet):
    def __init__(self, client, data: bytes | None = None):
        super().__init__(client, data)
        self.magic = b""
        self.substream_id = 0
        self.prudp_protocol_minor_version = 0
        self.supported_functions = 0
        self.initial_sequence_id = 0
        self.maximum_substream_id = 0

        if data is not None:
            try:
                self.decode()
            except NexError as e:
                raise NexError("[PRUDPv1] Error decoding packet data: " + str(e)) from e

    def decode(self) -> None:
        data = self.data

        if len(data) < 30:  # magic + header + signature
            raise NexError("[PRUDPv1] Packet length less than minimum")

        stream = StreamIn(data, self.sender.server)

        self.magic = stream.read_bytes_next(2)

        if self.magic != b"\xEA\xD0":
            raise NexError("PRUDPv1 packet magic did not match")

        self.version = stream.read_uint8()

        if self.version != 1:
            raise NexError("PRUDPv1 version did not match")

        options_length = stream.read_uint8()
        payload_size = stream.read_uint16le()

        self.source = stream.read_uint8()
        self.destination = stream.read_uint8()

        type_flags = stream.read_uint16le()

        self.packet_type = type_flags & 0xF
        self.flags = type_flags >> 4

        if self.packet_type not in VALID_TYPES:
            raise NexError("[PRUDPv1] Packet type not valid type")

        self.session_id = stream.read_uint8()
        self.substream_id = stream.read_uint8()
        self.sequence_id = stream.read_uint16le()

        self.signature = stream.read_bytes_next(16)

        if stream.remaining() < options_length:
            raise NexError("[PRUDPv1] Packet specific data size does not match")

        options = stream.read_bytes_next(options_length)

        self.decode_options(options)

        if payload_size > 0:
            if stream.remaining() < payload_size:
                raise NexError("[PRUDPv1] Packet data length less than payload length")

            payload_crypted = stream.read_bytes_next(payload_size)

            self.payload = payload_crypted

            if self.packet_type == DATA_PACKET and not self.has_flag(FLAG_MULTI_ACK):
                ciphered = self.sender.decipher.xor_key_stream(payload_crypted)

                request = RMCRequest()
                try:
                    request.from_bytes(ciphered)
                except NexError as e:
                    raise NexError("[PRUDPv1] Error parsing RMC request: " + str(e)) from e

                self.rmc_request = request

        calculated_signature = self.calculate_signature(
            data[2:14], self.sender.server_connection_signature, options, self.payload)

        if calculated_signature != self.signature:
            logger.error("PRUDPv1 calculated signature did not match")

    def to_bytes(self) -> bytes:
        if self.packet_type == DATA_PACKET:
            if not self.has_flag(FLAG_MULTI_ACK):
                payload = self.payload

                if payload is not None:
                    self.payload = self.sender.cipher.xor_key_stream(payload)

            if not self.has_flag(FLAG_HAS_SIZE):
                self.add_flag(FLAG_HAS_SIZE)

        type_flags = (self.packet_type | (self.flags << 4)) & 0xFFFF

        stream = StreamOut(self.sender.server)

        stream.write_uint16le(0xD0EA)  # magic v1
        stream.write_uint8(1)

        options = self.encode_options()
        options_length = len(options)

        stream.write_uint8(options_length)
        stream.write_uint16le(len(self.payload))
        stream.write_uint8(self.source)
        stream.write_uint8(self.destination)
        stream.write_uint16le(type_flags)
        stream.write_uint8(self.session_id)
        stream.write_uint8(self.substream_id)
        stream.write_uint16le(self.sequence_id)

        signature = self.calculate_signature(
            stream.to_bytes()[2:14], self.sender.client_connection_signature, options, self.payload)

        stream.write_bytes_next(signature)

        if options_length > 0:
            stream.write_bytes_next(options)

        if self.payload:
            stream.write_bytes_next(self.payload)

        return stream.to_bytes()

    def decode_options(self, options: bytes) -> None:
        options_stream = StreamIn(options, self.sender.server)

        while options_stream.byte_offset() != options_stream.byte_capacity():
            option_id = options_stream.read_uint8()
            option_size = options_stream.read_uint8()

            if option_id == OPTION_SUPPORTED_FUNCTIONS:
                supported_functions = options_stream.read_uint32le()
                self.sender.prudp_protocol_minor_version = supported_functions & 0xFF
                self.sender.supported_functions = supported_functions >> 8
            elif option_id == OPTION_CONNECTION_SIGNATURE:
                self.connection_signature = options_stream.read_bytes_next(option_size)
            elif option_id == OPTION_FRAGMENT_ID:
                self.fragment_id = options_stream.read_uint8()
            elif option_id == OPTION_INITIAL_SEQUENCE_ID:
                self.initial_sequence_id = options_stream.read_uint16le()
            elif option_id == OPTION_MAX_SUBSTREAM_ID:
                self.maximum_substream_id = options_stream.read_uint8()

    def encode_options(self) -> bytes:
        stream = StreamOut(self.sender.server)

        if self.packet_type in (SYN_PACKET, CONNECT_PACKET):
            stream.write_uint8(OPTION_SUPPORTED_FUNCTIONS)
            stream.write_uint8(4)
            stream.write_uint32le(self.prudp_protocol_minor_version | (self.supported_functions << 8))

            stream.write_uint8(OPTION_CONNECTION_SIGNATURE)
            stream.write_uint8(16)
            stream.write_bytes_next(self.connection_signature)

            if self.packet_type == CONNECT_PACKET:
                stream.write_uint8(OPTION_INITIAL_SEQUENCE_ID)
                stream.write_uint8(2)
                stream.write_uint16le(self.initial_sequence_id)

            stream.write_uint8(OPTION_MAX_SUBSTREAM_ID)
            stream.write_uint8(1)
            stream.write_uint8(self.maximum_substream_id)
        elif self.packet_type == DATA_PACKET:
            stream.write_uint8(OPTION_FRAGMENT_ID)
            stream.write_uint8(1)
            stream.write_uint8(self.fragment_id)

        return stream.to_bytes()

    def calculate_signature(self, header: bytes, connection_signature: bytes | None,
                            options: bytes, payload: bytes) -> bytes:
        sender = self.sender
        signature_base = struct.pack("<I", sender.signature_base & 0xFFFFFFFF)

        mac = hmac.new(sender.signature_key, digestmod=hashlib.md5)

        mac.update(header[4:])
        mac.update(sender.session_key or b"")
        mac.update(signature_base)
        mac.update(connection_signature or b"")
        mac.update(options)
        mac.update(payload or b"")

        return mac.digest()
