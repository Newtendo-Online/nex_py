"""Client de test PRUDPv1 : joue la poignée de main complète contre run_server.py.

    py test_client.py                    # vers 127.0.0.1:60000
    py test_client.py --port 60001 --access-key ridfebb9
"""
import argparse
import copy
import logging
import os
import socket
import struct
import sys

import nex
from nex import (CONNECT_PACKET, DATA_PACKET, DISCONNECT_PACKET, FLAG_ACK,
                 FLAG_MULTI_ACK, FLAG_NEEDS_ACK, FLAG_RELIABLE, SYN_PACKET,
                 Client, Errors, PacketV1, RMCRequest, Server)

failures = []


def check(name: str, ok: bool, detail: str = "") -> None:
    print(f"  [{'OK' if ok else 'ÉCHEC'}] {name}" + (f" — {detail}" if detail and not ok else ""))
    if not ok:
        failures.append(name)


class ErrorCounter(logging.Handler):
    """Compte les erreurs de la lib (signature/checksum invalides, etc.)."""
    def __init__(self):
        super().__init__(level=logging.ERROR)
        self.records = []

    def emit(self, record):
        self.records.append(record.getMessage())


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=60000)
    parser.add_argument("--access-key", default="ridfebb9")
    parser.add_argument("--timeout", type=float, default=4.0)
    args = parser.parse_args()

    errors = ErrorCounter()
    logging.getLogger("nex").addHandler(errors)

    config = Server()
    config.prudp_version = 1
    config.access_key = args.access_key
    config.nex_version = 30500

    target = (args.host, args.port)
    client = Client(target, config)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(args.timeout)

    def make(ptype, seq, flags, payload=b"", **attrs):
        p = PacketV1(client, None)
        p.source, p.destination, p.packet_type, p.sequence_id = 0xAF, 0xA1, ptype, seq
        for f in flags:
            p.add_flag(f)
        p.payload = payload
        for k, v in attrs.items():
            setattr(p, k, v)
        return p

    def receive():
        """Reçoit un datagramme. Retourne (paquet, clair) ; `clair` = payload déchiffré si c'est du RMC."""
        data, _ = sock.recvfrom(4096)
        decipher = copy.deepcopy(client.decipher)  # le décodage consomme le keystream : on garde une copie
        packet = PacketV1(client, data)
        plain = b""
        if packet.packet_type == DATA_PACKET and not packet.has_flag(FLAG_MULTI_ACK) and packet.payload:
            plain = decipher.xor_key_stream(packet.payload)
        return packet, plain

    print(f"Cible : {args.host}:{args.port} (PRUDPv1, access key {args.access_key!r})")

    try:
        # 1. SYN -> ACK avec la signature de connexion du serveur
        print("1. SYN")
        sock.sendto(make(SYN_PACKET, 0, [FLAG_NEEDS_ACK], connection_signature=bytes(16)).to_bytes(), target)
        ack, _ = receive()
        check("ACK reçu", ack.packet_type == SYN_PACKET and ack.has_flag(FLAG_ACK))
        check("signature de connexion serveur (16 octets)", len(ack.connection_signature) == 16)
        server_signature = ack.connection_signature

        # 2. CONNECT -> ACK
        print("2. CONNECT")
        my_signature = os.urandom(16)
        client.client_connection_signature = server_signature  # signe nos paquets sortants
        client.server_connection_signature = my_signature      # vérifie les paquets entrants
        connect = make(CONNECT_PACKET, 1, [FLAG_NEEDS_ACK], connection_signature=my_signature,
                       initial_sequence_id=10000)
        sock.sendto(connect.to_bytes(), target)
        ack, _ = receive()
        check("ACK reçu", ack.packet_type == CONNECT_PACKET and ack.has_flag(FLAG_ACK))

        # 3. DATA (requête RMC) -> ACK groupé + réponse RMC
        print("3. DATA (requête RMC protocole 10, méthode 1)")
        rmc = RMCRequest()
        rmc.protocol_id, rmc.call_id, rmc.method_id, rmc.parameters = 10, 4242, 1, b"hello"
        data = make(DATA_PACKET, 2, [FLAG_RELIABLE, FLAG_NEEDS_ACK], rmc.to_bytes(), fragment_id=0)
        sock.sendto(data.to_bytes(), target)

        got_multi_ack, response = False, None
        while not (got_multi_ack and response):
            packet, plain = receive()
            if packet.has_flag(FLAG_MULTI_ACK):
                got_multi_ack = True
            elif packet.packet_type == DATA_PACKET:
                response = plain
        check("ACK groupé reçu", got_multi_ack)

        size = struct.unpack_from("<I", response, 0)[0]
        protocol, success = response[4], response[5]
        error_code, call_id = struct.unpack_from("<II", response, 6)
        check("taille RMC cohérente", size == len(response) - 4)
        check("réponse = erreur (success=0)", success == 0)
        check("code d'erreur Core::NotImplemented",
              error_code == (Errors.Core.NotImplemented | nex.ERROR_MASK),
              f"reçu {nex.error_name_from_code(error_code & ~nex.ERROR_MASK)}")
        check("call_id renvoyé (4242)", call_id == 4242, f"reçu {call_id}")
        check("protocole renvoyé (10)", protocol == 10, f"reçu {protocol}")

        # 4. DISCONNECT
        print("4. DISCONNECT")
        sock.sendto(make(DISCONNECT_PACKET, 3, [FLAG_NEEDS_ACK]).to_bytes(), target)
        try:
            receive()
        except socket.timeout:
            pass  # le serveur peut ne rien répondre à un DISCONNECT sans ACK

    except socket.timeout:
        print("\nAucune réponse du serveur : est-il lancé (py run_server.py) ? Bon port ? Pare-feu ?")
        return 2
    except ConnectionResetError:
        print("\nConnexion refusée : le serveur n'écoute pas sur ce port.")
        return 2

    print("5. Intégrité")
    check("aucune erreur de signature / checksum côté client", not errors.records, "; ".join(errors.records))

    print()
    if failures:
        print(f"{len(failures)} vérification(s) échouée(s).")
        return 1
    print("Tout est OK : le serveur PRUDP fonctionne.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
