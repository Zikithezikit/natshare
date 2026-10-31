import unittest

from natshare import packet as pk


class PacketTest(unittest.TestCase):
    def test_ipv4_roundtrip(self):
        raw = pk.build_ipv4("10.0.0.1", "8.8.8.8", pk.UDP, b"hello")
        self.assertEqual(pk.checksum(raw[:20]), 0)
        ip = pk.parse_ipv4(raw)
        self.assertEqual((ip.src, ip.dst, ip.proto, ip.payload), ("10.0.0.1", "8.8.8.8", pk.UDP, b"hello"))

    def test_tcp_roundtrip(self):
        raw = pk.build_tcp("10.0.0.1", 1234, "1.1.1.1", 80, 5, 9, pk.SYN | pk.ACK, 100, b"data", mss=1400)
        seg = pk.parse_tcp(pk.parse_ipv4(raw).payload)
        self.assertEqual(
            (seg.sport, seg.dport, seg.seq, seg.ack, seg.window, seg.payload), (1234, 80, 5, 9, 100, b"data")
        )

    def test_udp_roundtrip(self):
        raw = pk.build_udp("10.0.0.1", 1, "1.1.1.1", 53, b"q")
        dg = pk.parse_udp(pk.parse_ipv4(raw).payload)
        self.assertEqual((dg.sport, dg.dport, dg.payload), (1, 53, b"q"))

    def test_icmp_echo_checksum(self):
        raw = pk.build_icmp_echo("1.1.1.1", "10.0.0.1", 7, 1, b"xy", reply=True)
        self.assertEqual(pk.checksum(pk.parse_ipv4(raw).payload), 0)

    def test_rejects_malformed(self):
        self.assertIsNone(pk.parse_ipv4(b"\x45\x00"))
        self.assertIsNone(pk.parse_ipv4(b"\x60" + b"\0" * 39))  # IPv6
        frag = bytearray(pk.build_ipv4("1.1.1.1", "2.2.2.2", pk.UDP, b"x"))
        frag[6] = 0x20  # MF set
        self.assertIsNone(pk.parse_ipv4(bytes(frag)))
        self.assertIsNone(pk.parse_tcp(b"short"))
        self.assertIsNone(pk.parse_udp(b"short"))
