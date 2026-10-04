import argparse
import logging
import sys

import nex
from nex import (DATA_PACKET, FLAG_NEEDS_ACK, FLAG_RELIABLE, Errors, PacketV0,
                 PacketV1, RMCResponse)


def safe(handler):
    """Un handler qui plante ne doit pas faire de bruit incompréhensible."""
    def wrapper(packet):
        try:
            handler(packet)
        except Exception:
            logging.getLogger("service").exception("Erreur dans le handler %s", handler.__name__)
    wrapper.__name__ = handler.__name__
    return wrapper


def main() -> int:
    parser = argparse.ArgumentParser(description="Serveur PRUDP de test")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=60000)
    parser.add_argument("--access-key", default="ridfebb9", help="clé d'accès du jeu (8 caractères)")
    parser.add_argument("--prudp-version", type=int, choices=(0, 1), default=1)
    parser.add_argument("--nex-version", type=int, default=30500)
    parser.add_argument("--minor-version", type=int, default=2, help="version mineure PRUDPv1")
    parser.add_argument("--ping-timeout", type=int, default=15, help="secondes avant ping/kick")
    parser.add_argument("-v", "--verbose", action="store_true", help="logs de debug")
    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s", datefmt="%H:%M:%S")
    log = logging.getLogger("service")

    server = nex.Server()
    server.prudp_version = args.prudp_version
    server.nex_version = args.nex_version
    server.prudp_protocol_minor_version = args.minor_version
    server.access_key = args.access_key
    server.ping_timeout = args.ping_timeout
    packet_class = PacketV0 if args.prudp_version == 0 else PacketV1

    def who(packet) -> str:
        return f"{packet.sender.address[0]}:{packet.sender.address[1]}"

    @safe
    def on_listening(_):
        log.info("Prêt. PRUDPv%d, access key %r, NEX %d", args.prudp_version, args.access_key, args.nex_version)

    @safe
    def on_syn(packet):
        log.info("SYN        de %s", who(packet))

    @safe
    def on_connect(packet):
        log.info("CONNECT    de %s", who(packet))

    @safe
    def on_data(packet):
        request = packet.rmc_request
        if request is None:
            return
        log.info("RMC        de %s : protocole=%d méthode=%d call_id=%d (%d octets de paramètres)",
                 who(packet), request.protocol_id, request.method_id, request.call_id, len(request.parameters))

        # Ici tu brancheras tes vrais protocoles. Pour l'instant : "pas implémenté".
        response = RMCResponse(request.protocol_id, request.call_id)
        response.set_error(Errors.Core.NotImplemented)

        reply = packet_class(packet.sender, None)
        reply.source = packet.destination
        reply.destination = packet.source
        reply.packet_type = DATA_PACKET
        reply.add_flag(FLAG_RELIABLE)
        reply.add_flag(FLAG_NEEDS_ACK)
        reply.payload = response.to_bytes()
        server.send(reply)

    @safe
    def on_ping(packet):
        log.info("PING       de %s", who(packet))

    @safe
    def on_disconnect(packet):
        log.info("DISCONNECT de %s", who(packet))

    @safe
    def on_kick(packet):
        log.info("KICK       %s", who(packet))

    for event, handler in (("Listening", on_listening), ("Syn", on_syn), ("Connect", on_connect),
                           ("Data", on_data), ("Ping", on_ping), ("Disconnect", on_disconnect),
                           ("Kick", on_kick)):
        server.on(event, handler)

    try:
        server.listen(f"{args.host}:{args.port}")
    except KeyboardInterrupt:
        log.info("Arrêt demandé (Ctrl+C).")
    except OSError as e:
        log.error("Impossible de démarrer le serveur sur %s:%d : %s", args.host, args.port, e)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
