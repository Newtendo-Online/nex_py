from __future__ import annotations

import os
import socket
import threading
import time
from collections import defaultdict
from typing import Any, Callable

from .client import Client
from .counter import Counter
from .errors import NexError
from .packet_flags import FLAG_ACK, FLAG_HAS_SIZE, FLAG_MULTI_ACK, FLAG_NEEDS_ACK, FLAG_RELIABLE
from .packet_types import (CONNECT_PACKET, DATA_PACKET, DISCONNECT_PACKET,
                           PING_PACKET, SYN_PACKET)
from .packet_v0 import PacketV0
from .packet_v1 import PacketV1
from .stream_out import StreamOut
from .utils import logger


def _discriminator(address: tuple) -> str:
    return f"{address[0]}:{address[1]}"


class Server:
    def __init__(self):
        self.socket: socket.socket | None = None
        self.clients: dict[str, Client] = {}
        self._clients_lock = threading.Lock()
        self.event_handlers: dict[str, list[Callable[[Any], None]]] = defaultdict(list)
        self.access_key = ""
        self.prudp_version = 1
        self.nex_version = 0
        self.prudp_protocol_minor_version = 0
        self.supported_functions = 0
        self.fragment_size = 1300
        self.resend_timeout = 1.5
        self.ping_timeout = 5
        self.kerberos_password = ""
        self.kerberos_key_size = 32
        self.kerberos_key_derivation = 0
        self.kerberos_ticket_version = 0
        self.connection_id_counter = Counter(10)

    def listen(self, address: str) -> None:
        host, _, port = address.rpartition(":")
        host = host or "0.0.0.0"

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((host, int(port)))
        self.socket = sock

        quit_event = threading.Event()
        errors: list[BaseException] = []

        for _ in range(os.cpu_count() or 1):
            threading.Thread(target=self._listen_datagram, args=(quit_event, errors), daemon=True).start()

        bound = sock.getsockname()
        logger.info("PRUDP server listening on address - %s:%s", bound[0], bound[1])

        self.emit("Listening", None)

        while not quit_event.wait(0.5):
            pass

        if errors:
            raise errors[0]

    def _listen_datagram(self, quit_event: threading.Event, errors: list) -> None:
        try:
            while True:
                self.handle_socket_message()
        except OSError as e:
            errors.append(e)
            quit_event.set()

    def handle_socket_message(self) -> None:
        data, addr = self.socket.recvfrom(64000)

        try:
            self._handle_datagram(data, addr)
        except Exception:
            logger.exception("Error while handling packet")

    def _handle_datagram(self, data: bytes, addr: tuple) -> None:
        discriminator = _discriminator(addr)

        with self._clients_lock:
            client = self.clients.get(discriminator)
            if client is None:
                client = Client(addr, self)
                self.clients[discriminator] = client

        try:
            if self.prudp_version == 0:
                packet = PacketV0(client, data)
            else:
                packet = PacketV1(client, data)
        except NexError:
            return

        client.increase_ping_timeout_time(self.ping_timeout)

        if packet.has_flag(FLAG_ACK) or packet.has_flag(FLAG_MULTI_ACK):
            return

        if packet.packet_type == SYN_PACKET:
            if client.pid != 0:
                self.emit("Disconnect", packet)
            client.reset()
            client.connected = True
            client.start_timeout_timer()
        elif packet.packet_type == CONNECT_PACKET:
            packet.sender.client_connection_signature = packet.connection_signature

        if packet.has_flag(FLAG_NEEDS_ACK):
            if packet.packet_type != CONNECT_PACKET or len(packet.payload) <= 0:
                threading.Thread(target=self.acknowledge_packet, args=(packet, None), daemon=True).start()

        if packet.packet_type == SYN_PACKET:
            self.emit("Syn", packet)
        elif packet.packet_type == CONNECT_PACKET:
            self.emit("Connect", packet)
        elif packet.packet_type == DATA_PACKET:
            self.emit("Data", packet)
        elif packet.packet_type == DISCONNECT_PACKET:
            self.emit("Disconnect", packet)
            self.kick(client)
        elif packet.packet_type == PING_PACKET:
            self.emit("Ping", packet)

        self.emit("Packet", packet)

    def on(self, event: str, handler: Callable[[Any], None]) -> None:
        self.event_handlers[event].append(handler)

    def emit(self, event: str, packet: Any) -> None:
        for handler in list(self.event_handlers.get(event, ())):
            threading.Thread(target=handler, args=(packet,), daemon=True).start()

    def client_connected(self, client: Client) -> bool:
        return _discriminator(client.address) in self.clients

    def kick(self, client: Client) -> None:
        if self.prudp_version == 0:
            packet = PacketV0(client, None)
        else:
            packet = PacketV1(client, None)

        self.emit("Kick", packet)
        client.connected = False
        with self._clients_lock:
            self.clients.pop(_discriminator(client.address), None)

    def find_client_from_pid(self, pid: int) -> Client | None:
        for client in list(self.clients.values()):
            if client.pid == pid:
                return client
        return None

    def find_client_from_connection_id(self, rvcid: int) -> Client | None:
        for client in list(self.clients.values()):
            if client.connection_id == rvcid:
                return client
        return None

    def send_ping(self, client: Client) -> None:
        if self.prudp_version == 0:
            ping_packet = PacketV0(client, None)
        else:
            ping_packet = PacketV1(client, None)

        ping_packet.source = 0xA1
        ping_packet.destination = 0xAF
        ping_packet.packet_type = PING_PACKET
        ping_packet.add_flag(FLAG_NEEDS_ACK)
        ping_packet.add_flag(FLAG_RELIABLE)

        self.send(ping_packet)

    def acknowledge_packet(self, packet, payload: bytes | None = None) -> None:
        sender = packet.sender

        if self.prudp_version == 0:
            ack_packet = PacketV0(sender, None)
        else:
            ack_packet = PacketV1(sender, None)

        ack_packet.source = packet.destination
        ack_packet.destination = packet.source
        ack_packet.packet_type = packet.packet_type
        ack_packet.sequence_id = packet.sequence_id
        ack_packet.fragment_id = packet.fragment_id
        ack_packet.add_flag(FLAG_ACK)
        ack_packet.add_flag(FLAG_HAS_SIZE)

        if payload is not None:
            ack_packet.payload = payload

        if self.prudp_version == 1:
            ack_packet.version = 1
            ack_packet.substream_id = 0
            ack_packet.add_flag(FLAG_HAS_SIZE)

            if packet.packet_type in (SYN_PACKET, CONNECT_PACKET):
                ack_packet.prudp_protocol_minor_version = packet.sender.prudp_protocol_minor_version
                ack_packet.maximum_substream_id = 0

            if packet.packet_type == SYN_PACKET:
                server_connection_signature = os.urandom(16)

                ack_packet.sender.server_connection_signature = server_connection_signature
                ack_packet.connection_signature = server_connection_signature

            if packet.packet_type == CONNECT_PACKET:
                ack_packet.connection_signature = bytes(16)
                ack_packet.initial_sequence_id = 10000

            if packet.packet_type == DATA_PACKET:
                ack_packet.clear_flag(FLAG_ACK)
                ack_packet.add_flag(FLAG_MULTI_ACK)

                payload_stream = StreamOut(self)

                if self.prudp_protocol_minor_version >= 2:
                    ack_packet.sequence_id = 0
                    ack_packet.substream_id = 1

                    payload_stream.write_uint8(0)                    # substream ID
                    payload_stream.write_uint8(0)                    
                    payload_stream.write_uint16le(packet.sequence_id)  # sequence ID

                ack_packet.payload = payload_stream.to_bytes()

        self.send_raw(sender.address, ack_packet.to_bytes())

    def send(self, packet) -> None:
        data = packet.payload
        fragments = len(data) // self.fragment_size

        fragment_id = 1
        for _ in range(fragments + 1):
            time.sleep(0.5)
            if len(data) < self.fragment_size:
                packet.payload = data
                self.send_fragment(packet, 0)
            else:
                packet.payload = data[:self.fragment_size]
                self.send_fragment(packet, fragment_id)

                data = data[self.fragment_size:]
                fragment_id = (fragment_id + 1) & 0xFF

    def send_fragment(self, packet, fragment_id: int) -> None:
        data = packet.payload
        client = packet.sender

        packet.fragment_id = fragment_id
        packet.payload = data
        packet.sequence_id = client.sequence_id_out.increment() & 0xFFFF

        self.send_raw(client.address, packet.to_bytes())

    def send_raw(self, address: tuple, data: bytes) -> None:
        self.socket.sendto(data, address)
