"""Client PRUDP (client.go)."""
from __future__ import annotations

import threading
from typing import Callable, TYPE_CHECKING

from .counter import Counter
from .rc4 import RC4
from .utils import md5_hash, sum_bytes

if TYPE_CHECKING:
    from .server import Server


def _start_timer(seconds: float, function: Callable[[], None]) -> threading.Timer:
    timer = threading.Timer(seconds, function)
    timer.daemon = True
    timer.start()
    return timer


class Client:
    """Client PRUDP connecté ou non. `address` est un tuple (ip, port)."""

    def __init__(self, address: tuple, server: Server):
        self.address = address
        self.server = server
        self.cipher: RC4 | None = None
        self.decipher: RC4 | None = None
        self.prudp_protocol_minor_version = 0
        self.supported_functions = 0
        self.signature_key = b""
        self.signature_base = 0
        self.secure_key = b""
        self.server_connection_signature: bytes | None = None
        self.client_connection_signature: bytes | None = None
        self.session_id = 0
        self.session_key: bytes | None = None
        self.sequence_id_in = Counter(0)
        self.sequence_id_out = Counter(0)
        self.pid = 0
        self.local_station_url = ""
        self.connection_id = 0
        self._ping_check_timer: threading.Timer | None = None
        self._ping_kick_timer: threading.Timer | None = None
        self.connected = False

        self.reset()

    def reset(self) -> None:
        """Remet le client à ses valeurs par défaut."""
        self.sequence_id_in = Counter(0)
        self.sequence_id_out = Counter(0)

        self.update_access_key(self.server.access_key)
        self.update_rc4_key(b"CD&ML")

        if self.server.prudp_version == 0:
            self.server_connection_signature = bytes(4)
            self.client_connection_signature = bytes(4)
        else:
            self.server_connection_signature = b""
            self.client_connection_signature = b""

        self.connected = False

    def set_port(self, port: int) -> None:
        self.address = (self.address[0], port)

    def update_rc4_key(self, rc4_key: bytes) -> None:
        """Définit la clé du flux RC4 (cipher = sortant, decipher = entrant)."""
        self.cipher = RC4(rc4_key)
        self.decipher = RC4(rc4_key)

    def update_access_key(self, access_key: str) -> None:
        """Définit la signature base et la signature key du client."""
        self.signature_base = sum_bytes(access_key.encode())
        self.signature_key = md5_hash(access_key.encode())

    # -- timers de ping ------------------------------------------------------
    def _ping_check(self) -> None:
        # si on n'a pas reçu de ping *du* client, on lui en envoie un
        self.server.send_ping(self)
        # si on ne reçoit *toujours* rien, il est parti
        self._ping_kick_timer = _start_timer(self.server.ping_timeout, lambda: self.server.kick(self))

    def increase_ping_timeout_time(self, seconds: float) -> None:
        """Repousse le timer de vérification de `seconds` secondes."""
        # on stoppe le kick timer si on reçoit quelque chose
        if self._ping_kick_timer is not None:
            self._ping_kick_timer.cancel()
        # et on réarme le check timer (threading.Timer n'a pas de reset())
        if self._ping_check_timer is not None:
            self._ping_check_timer.cancel()
            self._ping_check_timer = _start_timer(seconds, self._ping_check)

    def start_timeout_timer(self) -> None:
        """Démarre le timer de timeout des paquets."""
        self._ping_check_timer = _start_timer(self.server.ping_timeout, self._ping_check)
