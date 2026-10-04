import socket
import struct
import threading
import time
import unittest

import nex
from nex import (Client, DataHolder, Errors, NexError, PacketV0, PacketV1, RC4,
                 RMCRequest, RMCResponse, Result, Server, StationURL, StreamIn,
                 StreamOut, Structure, Ticket, TicketInternalData, DateTime)


def make_server(prudp_version=1, access_key="abcd1234", ticket_version=0):
    s = Server()
    s.prudp_version = prudp_version
    s.access_key = access_key
    s.nex_version = 30500
    s.kerberos_ticket_version = ticket_version
    return s


class CryptoTests(unittest.TestCase):
    def test_rc4_known_vectors(self):
        self.assertEqual(RC4(b"Key").xor_key_stream(b"Plaintext").hex().upper(), "BBF316E8D940AF0AD3")
        self.assertEqual(RC4(b"Wiki").xor_key_stream(b"pedia").hex().upper(), "1021BF0420")
        # le keystream est à état
        c = RC4(b"Key")
        a = c.xor_key_stream(b"Plain") + c.xor_key_stream(b"text")
        self.assertEqual(a.hex().upper(), "BBF316E8D940AF0AD3")

    def test_kerberos_roundtrip_both_versions(self):
        for version in (0, 1):
            srv = make_server(ticket_version=version)
            t = TicketInternalData()
            t.timestamp = DateTime(123456789)
            t.user_pid = 1337
            t.session_key = bytes(range(32))
            blob = t.encrypt(b"k" * 16, StreamOut(srv))

            out = TicketInternalData()
            out.decrypt(StreamIn(blob, srv), b"k" * 16)
            self.assertEqual((out.timestamp.value, out.user_pid, out.session_key),
                             (123456789, 1337, bytes(range(32))))

    def test_kerberos_hmac_detects_tampering(self):
        enc = nex.KerberosEncryption(b"key").encrypt(b"hello world")
        self.assertTrue(nex.KerberosEncryption(b"key").validate(enc))
        self.assertFalse(nex.KerberosEncryption(b"key").validate(enc[:-1] + b"\x00"))

    def test_ticket_encrypt(self):
        srv = make_server()
        t = Ticket()
        t.session_key, t.target_pid, t.internal_data = b"s" * 32, 7, b"abc"
        blob = t.encrypt(b"x" * 16, StreamOut(srv))
        dec = nex.KerberosEncryption(b"x" * 16).decrypt(blob)
        self.assertEqual(dec, b"s" * 32 + struct.pack("<I", 7) + struct.pack("<I", 3) + b"abc")

    def test_derive_key(self):
        import hashlib
        pw = b"pw"
        for _ in range(65000 + 5 % 1024):
            pw = hashlib.md5(pw).digest()
        self.assertEqual(nex.derive_kerberos_key(5, b"pw"), pw)


class StreamTests(unittest.TestCase):
    def test_roundtrip(self):
        srv = make_server()
        o = StreamOut(srv)
        o.write_bool(True); o.write_uint8(200); o.write_uint16le(65000)
        o.write_uint32le(4_000_000_000); o.write_int32le(-5); o.write_uint64le(2**63 + 1)
        o.write_string("héllo"); o.write_buffer(b"\x01\x02"); o.write_qbuffer(b"\x03")
        o.write_list_uint32le([1, 2, 3]); o.write_list_string(["a", "b"])
        o.write_list_qbuffer([b"x", b"yz"])
        i = StreamIn(o.to_bytes(), srv)
        self.assertEqual(i.read_bool(), True)
        self.assertEqual(i.read_uint8(), 200)
        self.assertEqual(i.read_uint16le(), 65000)
        self.assertEqual(i.read_uint32le(), 4_000_000_000)
        self.assertEqual(i.read_int32le(), -5)
        self.assertEqual(i.read_uint64le(), 2**63 + 1)
        self.assertEqual(i.read_string(), "héllo")
        self.assertEqual(i.read_buffer(), b"\x01\x02")
        self.assertEqual(i.read_qbuffer(), b"\x03")
        self.assertEqual(i.read_list_uint32le(), [1, 2, 3])
        self.assertEqual(i.read_list_string(), ["a", "b"])
        self.assertEqual(i.read_list_qbuffer(), [b"x", b"yz"])
        self.assertEqual(i.remaining(), 0)

    def test_exact_wire_format(self):
        o = StreamOut(None)
        o.write_string("ab")
        self.assertEqual(o.to_bytes(), b"\x03\x00ab\x00")
        o = StreamOut(None); o.write_buffer(b"xy")
        self.assertEqual(o.to_bytes(), b"\x02\x00\x00\x00xy")

    def test_truncated_data_raises(self):
        with self.assertRaises(NexError):
            StreamIn(b"\xff\xff\x00", None).read_string()
        with self.assertRaises(NexError):
            StreamIn(b"\x01", None).read_uint32le()

    def test_variant_and_map(self):
        i = StreamIn(b"\x01" + struct.pack("<q", -9) + b"\x02" + struct.pack("<d", 1.5)
                     + b"\x03\x01" + b"\x06" + struct.pack("<Q", 7), None)
        self.assertEqual([i.read_variant() for _ in range(4)], [-9, 1.5, True, 7])
        o = StreamOut(None); o.write_uint32le(1); o.write_string("k"); o.write_uint8(4); o.write_string("v")
        i = StreamIn(o.to_bytes(), None)
        self.assertEqual(i.read_map(i.read_string, i.read_variant), {"k": "v"})


class Point(Structure):
    def __init__(self):
        self.x = 0
        self.y = 0

    def extract_from_stream(self, stream):
        self.x = stream.read_uint32le(); self.y = stream.read_uint32le()

    def to_bytes(self, stream):
        stream.write_uint32le(self.x); stream.write_uint32le(self.y)
        return stream.to_bytes()


class TypesTests(unittest.TestCase):
    def test_structure_headers_by_nex_version(self):
        for ver, extra in ((30000, 0), (30500, 5)):
            srv = make_server(); srv.nex_version = ver
            p = Point(); p.x, p.y = 1, 2
            o = StreamOut(srv); o.write_structure(p)
            self.assertEqual(len(o.to_bytes()), 8 + extra)
            q = StreamIn(o.to_bytes(), srv).read_structure(Point())
            self.assertEqual((q.x, q.y), (1, 2))

    def test_data_holder_roundtrip_has_no_duplication(self):
        nex.register_data_holder_type(Point())
        # NB : comme en Go, DataHolder.to_bytes n'écrit pas l'en-tête de structure alors que
        # read_structure le saute dès nex_version >= 30500 -> on teste avec une version < 3.5.
        srv = make_server(); srv.nex_version = 30000
        dh = DataHolder(); dh.type_name = "Point"
        dh.object_data = Point(); dh.object_data.x, dh.object_data.y = 3, 4
        o = StreamOut(srv); o.write_uint8(0xAA); o.write_data_holder(dh)
        raw = o.to_bytes()
        self.assertEqual(raw[0], 0xAA)
        i = StreamIn(raw, srv); i.read_uint8()
        out = i.read_data_holder()
        self.assertEqual((out.type_name, out.object_data.x, out.object_data.y), ("Point", 3, 4))
        self.assertEqual(i.remaining(), 0)

    def test_station_url(self):
        s = StationURL("prudps:/address=1.2.3.4;port=60000;CID=1;PID=2;sid=1;stream=10;type=2")
        self.assertEqual((s.scheme, s.address, s.port, s.cid, s.pid, s.transport_type),
                         ("prudps", "1.2.3.4", "60000", "1", "2", "2"))
        self.assertEqual(s.encode_to_string(),
                         "prudps:/address=1.2.3.4;port=60000;stream=10;sid=1;CID=1;PID=2;type=2")

    def test_result_and_errors(self):
        self.assertTrue(Result.new_success(0x80010001).is_success())
        r = Result.new_error(Errors.Core.Unknown)
        self.assertTrue(r.is_error()); self.assertEqual(r.code, 0x80010001)
        self.assertEqual(nex.error_name_from_code(Errors.Core.Unknown), "Core::Unknown")
        self.assertTrue(nex.error_name_from_code(1).startswith("Invalid Error Code"))

    def test_datetime(self):
        self.assertEqual(DateTime().make(2024, 5, 17, 13, 45, 30),
                         30 | (45 << 6) | (13 << 12) | (17 << 17) | (5 << 22) | (2024 << 26))


class RMCTests(unittest.TestCase):
    def test_request_roundtrip(self):
        r = RMCRequest(); r.protocol_id, r.call_id, r.method_id, r.parameters = 10, 99, 3, b"params"
        out = RMCRequest(); out.from_bytes(r.to_bytes())
        self.assertEqual((out.protocol_id, out.call_id, out.method_id, out.parameters), (10, 99, 3, b"params"))

    def test_custom_id_request_parameters_offset(self):
        r = RMCRequest(); r.protocol_id, r.custom_id, r.call_id, r.method_id, r.parameters = 0x7F, 5, 1, 2, b"zz"
        out = RMCRequest(); out.from_bytes(r.to_bytes())
        self.assertEqual((out.custom_id, out.parameters), (5, b"zz"))

    def test_bad_sizes(self):
        with self.assertRaises(NexError): RMCRequest().from_bytes(b"short")
        with self.assertRaises(NexError): RMCRequest().from_bytes(b"\xff\x00\x00\x00" + b"\x00" * 10)

    def test_response_bytes(self):
        r = RMCResponse(10, 99); r.set_success(3, b"ok")
        self.assertEqual(r.to_bytes(), struct.pack("<I", 12 + 2 + 0) [:0] + struct.pack("<I", 1 + 1 + 4 + 4 + 2)
                         + bytes([10, 1]) + struct.pack("<I", 99) + struct.pack("<I", 3 | 0x8000) + b"ok")
        e = RMCResponse(10, 99); e.set_error(Errors.Core.Unknown)
        self.assertEqual(e.to_bytes()[4 + 2:4 + 6], struct.pack("<I", 0x80010001))


def rmc_payload():
    r = RMCRequest(); r.protocol_id, r.call_id, r.method_id, r.parameters = 10, 1, 2, b"hello"
    return r.to_bytes()


class PacketTests(unittest.TestCase):
    def _roundtrip(self, cls, version):
        srv = make_server(version)
        a, b = Client(("1.1.1.1", 1), srv), Client(("2.2.2.2", 2), srv)  # même clé RC4 initiale
        a.session_key = b.session_key = b"\x11" * 32
        p = cls(a, None)
        p.source, p.destination, p.packet_type = 0xAF, 0xA1, nex.DATA_PACKET
        p.add_flag(nex.FLAG_RELIABLE); p.add_flag(nex.FLAG_NEEDS_ACK)
        p.sequence_id, p.fragment_id, p.payload = 7, 0, rmc_payload()
        if version == 1:
            b.server_connection_signature = a.client_connection_signature  # signatures cohérentes
        with self.assertNoLogs("nex", level="ERROR"):
            wire = p.to_bytes()
            q = cls(b, wire)
        self.assertEqual((q.source, q.destination, q.packet_type, q.sequence_id),
                         (0xAF, 0xA1, nex.DATA_PACKET, 7))
        self.assertTrue(q.has_flag(nex.FLAG_RELIABLE) and q.has_flag(nex.FLAG_HAS_SIZE))
        self.assertEqual((q.rmc_request.protocol_id, q.rmc_request.parameters), (10, b"hello"))
        self.assertNotIn(b"hello", wire)  # bien chiffré

    def test_v0_roundtrip(self):
        self._roundtrip(PacketV0, 0)

    def test_v1_roundtrip(self):
        self._roundtrip(PacketV1, 1)

    def test_v0_friends_server_signature(self):
        srv = make_server(0, access_key="ridfebb9")
        c = Client(("1.1.1.1", 1), srv)
        p = PacketV0(c, None); p.packet_type = nex.DATA_PACKET
        self.assertEqual(p.calculate_signature(), struct.pack("<I", 0x12345678))

    def test_v0_checksum_mismatch_is_logged(self):
        srv = make_server(0)
        a, b = Client(("1.1.1.1", 1), srv), Client(("2.2.2.2", 2), srv)
        p = PacketV0(a, None); p.packet_type = nex.PING_PACKET
        wire = bytearray(p.to_bytes()); wire[-1] ^= 0xFF
        with self.assertLogs("nex", level="ERROR"):
            PacketV0(b, bytes(wire))

    def test_decode_errors(self):
        srv = make_server(1)
        c = Client(("1.1.1.1", 1), srv)
        with self.assertRaises(NexError): PacketV1(c, b"\x00" * 10)
        with self.assertRaises(NexError): PacketV1(c, b"\x00" * 40)  # mauvais magic
        with self.assertRaises(NexError): PacketV0(Client(("1.1.1.1", 1), make_server(0)), b"\x00" * 3)

    def test_v1_syn_options_roundtrip(self):
        srv = make_server(1)
        a, b = Client(("1.1.1.1", 1), srv), Client(("2.2.2.2", 2), srv)
        p = PacketV1(a, None)
        p.packet_type, p.source, p.destination = nex.SYN_PACKET, 0xAF, 0xA1
        p.connection_signature = bytes(range(16)); p.prudp_protocol_minor_version = 2
        q = PacketV1(b, p.to_bytes())
        self.assertEqual(q.connection_signature, bytes(range(16)))
        self.assertEqual(b.prudp_protocol_minor_version, 2)


class ServerTests(unittest.TestCase):
    def test_syn_gets_ack_and_event(self):
        srv = make_server(1)
        srv.ping_timeout = 30
        seen = threading.Event()
        srv.on("Syn", lambda p: seen.set())
        threading.Thread(target=srv.listen, args=("127.0.0.1:0",), daemon=True).start()
        for _ in range(100):
            if srv.socket is not None and srv.socket.getsockname()[1]:
                break
            time.sleep(0.02)
        port = srv.socket.getsockname()[1]

        cli_srv = make_server(1)
        cli = Client(("127.0.0.1", port), cli_srv)
        syn = PacketV1(cli, None)
        syn.packet_type, syn.source, syn.destination = nex.SYN_PACKET, 0xAF, 0xA1
        syn.add_flag(nex.FLAG_NEEDS_ACK)
        syn.connection_signature = bytes(16)

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); sock.settimeout(3)
        sock.sendto(syn.to_bytes(), ("127.0.0.1", port))
        data, _ = sock.recvfrom(2048)
        ack = PacketV1(Client(("127.0.0.1", port), cli_srv), data)
        self.assertEqual(ack.packet_type, nex.SYN_PACKET)
        self.assertTrue(ack.has_flag(nex.FLAG_ACK))
        self.assertEqual((ack.source, ack.destination), (0xA1, 0xAF))
        self.assertEqual(len(ack.connection_signature), 16)
        self.assertTrue(seen.wait(3))
        self.assertEqual(len(srv.clients), 1)

    def test_kick_and_find(self):
        srv = make_server(1)
        c = Client(("9.9.9.9", 9), srv); c.pid = 42; c.connection_id = 77
        srv.clients["9.9.9.9:9"] = c
        self.assertIs(srv.find_client_from_pid(42), c)
        self.assertIs(srv.find_client_from_connection_id(77), c)
        kicked = threading.Event(); srv.on("Kick", lambda p: kicked.set())
        srv.kick(c)
        self.assertTrue(kicked.wait(2)); self.assertFalse(srv.client_connected(c))


if __name__ == "__main__":
    unittest.main()
