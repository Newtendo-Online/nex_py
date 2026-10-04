"""Paquet PRUDP générique (packet.go, packet_interface.go)."""
from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .client import Client
    from .rmc import RMCRequest


class Packet:
    """Base commune de PacketV0 et PacketV1.

    Les getters/setters Go sont remplacés par de simples attributs ; seuls
    `has_flag`, `add_flag` et `clear_flag` restent des méthodes.
    `to_bytes()` (= `Bytes()` en Go) est implémenté par les sous-classes.
    """

    def __init__(self, sender: Client, data: bytes | None):
        self.sender = sender
        self.data = data  # octets ayant servi à créer le paquet (≠ to_bytes())
        self.version = 0
        self.source = 0
        self.destination = 0
        self.packet_type = 0
        self.flags = 0
        self.session_id = 0
        self.signature = b""
        self.sequence_id = 0
        self.connection_signature = b""
        self.fragment_id = 0
        self.payload = b""
        self.rmc_request: RMCRequest | None = None

    def has_flag(self, flag: int) -> bool:
        return self.flags & flag != 0

    def add_flag(self, flag: int) -> None:
        self.flags |= flag

    def clear_flag(self, flag: int) -> None:
        self.flags &= ~flag & 0xFFFF

    def to_bytes(self) -> bytes:
        raise NotImplementedError
