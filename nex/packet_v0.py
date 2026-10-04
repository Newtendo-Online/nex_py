"""Paquet PRUDPv0 (packet_v0.go)."""
from __future__ import annotations

import hashlib
import hmac
import struct

from .errors import NexError
from .packet import Packet
from .packet_flags import FLAG_ACK, FLAG_HAS_SIZE
from .packet_types import (CONNECT_PACKET, DATA_PACKET, DISCONNECT_PACKET,
                           SYN_PACKET, VALID_TYPES)
from .rmc import RMCRequest
from .stream_in import StreamIn
from .stream_out import StreamOut
from .utils import logger, sum_bytes


class PacketV0(Packet):
    def __init__(self, client, data: bytes | None = None):
        super().__init__(client, data)
        self.checksum = 0

        if data is not None:
            try:
                self.decode()
            except NexError as e:
                raise NexError("[PRUDPv0] Error decoding packet data: " + str(e)) from e

    def decode(self) -> None:
        data = self.data

        if len(data) < 9:
            raise NexError("[PRUDPv0] Packet length less than header minimum")

        checksum_size = 1

        stream = StreamIn(data, self.sender.server)

        self.source = stream.read_uint8()
        self.destination = stream.read_uint8()

        type_flags = stream.read_uint16le()

        self.session_id = stream.read_uint8()
        self.signature = stream.read_bytes_next(4)
        self.sequence_id = stream.read_uint16le()

        self.packet_type = type_flags & 0xF
        self.flags = type_flags >> 4

        if self.packet_type not in VALID_TYPES:
            raise NexError("[PRUDPv0] Packet type not valid type")

        if self.packet_type in (SYN_PACKET, CONNECT_PACKET):
            if stream.remaining() < 4:
                raise NexError("[PRUDPv0] Packet specific data not large enough for connection signature")

            self.connection_signature = stream.read_bytes_next(4)

        if self.packet_type == DATA_PACKET:
            if stream.remaining() < 1:
                raise NexError("[PRUDPv0] Packet specific data not large enough for fragment ID")

            self.fragment_id = stream.read_uint8()

        if self.has_flag(FLAG_HAS_SIZE):
            if stream.remaining() < 2:
                raise NexError("[PRUDPv0] Packet specific data not large enough for payload size")

            payload_size = stream.read_uint16le()
        else:
            payload_size = (len(data) - stream.byte_offset() - checksum_size) & 0xFFFF

        if payload_size > 0:
            if stream.remaining() < payload_size:
                raise NexError("[PRUDPv0] Packet data length less than payload length")

            payload_crypted = stream.read_bytes_next(payload_size)

            self.payload = payload_crypted

            if self.packet_type == DATA_PACKET:
                ciphered = self.sender.decipher.xor_key_stream(payload_crypted)

                request = RMCRequest()
                try:
                    request.from_bytes(ciphered)
                except NexError as e:
                    raise NexError("[PRUDPv0] Error parsing RMC request: " + str(e)) from e

                self.rmc_request = request

        if stream.remaining() < checksum_size:
            raise NexError("[PRUDPv0] Packet data length less than checksum length")

        self.checksum = stream.read_uint8()

        packet_body = stream.to_bytes()

        calculated_checksum = self.calculate_checksum(packet_body[:len(packet_body) - checksum_size])

        if calculated_checksum != self.checksum:
            logger.error("PRUDPv0 packet calculated checksum did not match")

    def to_bytes(self) -> bytes:
        if self.packet_type == DATA_PACKET:
            if self.has_flag(FLAG_ACK):
                self.payload = b""
            else:
                payload = self.payload

                if payload is not None:
                    self.payload = self.sender.cipher.xor_key_stream(payload)

            if not self.has_flag(FLAG_HAS_SIZE):
                self.add_flag(FLAG_HAS_SIZE)

        type_flags = (self.packet_type | (self.flags << 4)) & 0xFFFF

        stream = StreamOut(self.sender.server)
        packet_signature = self.calculate_signature()

        stream.write_uint8(self.source)
        stream.write_uint8(self.destination)
        stream.write_uint16le(type_flags)
        stream.write_uint8(self.session_id)
        stream.write_bytes_next(packet_signature)
        stream.write_uint16le(self.sequence_id)

        options = self.encode_options()
        if len(options) > 0:
            stream.write_bytes_next(options)

        payload = self.payload
        if payload:
            stream.write_bytes_next(payload)

        checksum = self.calculate_checksum(stream.to_bytes())

        stream.write_uint8(checksum)

        return stream.to_bytes()

    def calculate_signature(self) -> bytes:
        sender = self.sender
        server = sender.server

        # Le serveur Friends gère les signatures différemment (access key "ridfebb9")
        if server.access_key == "ridfebb9":
            if self.packet_type == DATA_PACKET:
                payload = self.payload

                if not payload:
                    signature = StreamOut(server)
                    signature.write_uint32le(0x12345678)
                    return signature.to_bytes()

                return hmac.new(sender.signature_key, payload, hashlib.md5).digest()[:4]

            client_connection_signature = sender.client_connection_signature

            if client_connection_signature is not None:
                return client_connection_signature

            return b"\x00\x00\x00\x00"

        # Gestion normale des signatures
        if self.packet_type in (DATA_PACKET, DISCONNECT_PACKET):
            payload = StreamOut(server)
            session_key = sender.session_key
            if session_key is not None:
                payload.write_bytes_next(session_key)
            payload.write_uint16le(self.sequence_id)
            payload.write_uint8(self.fragment_id)
            if self.payload:
                payload.write_bytes_next(self.payload)

            return hmac.new(sender.signature_key, payload.to_bytes(), hashlib.md5).digest()[:4]

        client_connection_signature = sender.client_connection_signature

        if client_connection_signature is not None:
            return client_connection_signature

        return b""

    def encode_options(self) -> bytes:
        stream = StreamOut(self.sender.server)

        if self.packet_type == SYN_PACKET:
            stream.write_bytes_next(self.sender.server_connection_signature)

        if self.packet_type == CONNECT_PACKET:
            stream.write_bytes_next(b"\x00\x00\x00\x00")

        if self.packet_type == DATA_PACKET:
            stream.write_uint8(self.fragment_id)

        if self.has_flag(FLAG_HAS_SIZE):
            payload = self.payload

            if payload is not None:
                stream.write_uint16le(len(payload))
            else:
                stream.write_uint16le(0)

        return stream.to_bytes()

    def calculate_checksum(self, data: bytes) -> int:
        signature_base = self.sender.signature_base
        steps = len(data) // 4
        temp = 0

        for i in range(steps):
            temp += struct.unpack_from("<I", data, i * 4)[0]

        temp &= 0xFFFFFFFF

        buff = struct.pack("<I", temp)

        checksum = signature_base
        checksum += sum_bytes(data[len(data) & ~3:])
        checksum += sum_bytes(buff)

        return checksum & 0xFF
