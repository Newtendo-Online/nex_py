from __future__ import annotations

import hashlib
import hmac
import os
from typing import TYPE_CHECKING

from .nex_types import DateTime
from .rc4 import RC4
from .stream_in import StreamIn
from .stream_out import StreamOut
from .utils import logger, md5_hash


class KerberosEncryption:
    def __init__(self, key: bytes):
        self.key = bytes(key)
        self.cipher = RC4(self.key)

    def encrypt(self, buffer: bytes) -> bytes:
        encrypted = self.cipher.xor_key_stream(buffer)
        mac = hmac.new(self.key, encrypted, hashlib.md5).digest()
        return encrypted + mac

    def decrypt(self, buffer: bytes) -> bytes:
        if not self.validate(buffer):
            logger.error("Keberos hmac validation failed")

        encrypted = buffer[:len(buffer) - 0x10]
        return self.cipher.xor_key_stream(encrypted)

    def validate(self, buffer: bytes) -> bool:
        offset = len(buffer) - 0x10
        data, checksum = buffer[:offset], buffer[offset:]
        mac = hmac.new(self.key, data, hashlib.md5).digest()
        return hmac.compare_digest(mac, checksum)


class Ticket:
    def __init__(self):
        self.session_key = b""
        self.target_pid = 0
        self.internal_data = b""

    def encrypt(self, key: bytes, stream: StreamOut) -> bytes:
        encryption = KerberosEncryption(key)

        stream.write_bytes_next(self.session_key)
        stream.write_uint32le(self.target_pid)
        stream.write_buffer(self.internal_data)

        return encryption.encrypt(stream.to_bytes())


class TicketInternalData:
    def __init__(self):
        self.timestamp = DateTime(0)
        self.user_pid = 0
        self.session_key = b""

    def encrypt(self, key: bytes, stream: StreamOut) -> bytes:
        stream.write_uint64le(self.timestamp.value)
        stream.write_uint32le(self.user_pid)

        stream.write_bytes_next(self.session_key)

        data = stream.to_bytes()

        if stream.server.kerberos_ticket_version == 1:
            ticket_key = os.urandom(16)
            final_key = md5_hash(key + ticket_key)

            encrypted = KerberosEncryption(final_key).encrypt(data)

            final_stream = StreamOut(stream.server)
            final_stream.write_buffer(ticket_key)
            final_stream.write_buffer(encrypted)

            return final_stream.to_bytes()

        return KerberosEncryption(key).encrypt(data)

    def decrypt(self, stream: StreamIn, key: bytes) -> None:
        server = stream.server

        if server.kerberos_ticket_version == 1:
            ticket_key = stream.read_buffer()
            data = stream.read_buffer()

            key = md5_hash(key + ticket_key)
            stream = StreamIn(data, server)

        decrypted = KerberosEncryption(key).decrypt(stream.to_bytes())
        stream = StreamIn(decrypted, server)

        self.timestamp = stream.read_datetime()
        self.user_pid = stream.read_uint32le()
        self.session_key = stream.read_bytes_next(server.kerberos_key_size)


def derive_kerberos_key(pid: int, password: bytes) -> bytes:
    for _ in range(65000 + pid % 1024):
        password = md5_hash(password)

    return password
