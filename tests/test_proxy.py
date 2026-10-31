import ipaddress
import socket
import threading
import time
import unittest

from natshare import packet as pk
from natshare.proxy import Proxy

CLIENT, SERVER_IP = "10.42.0.20", "127.0.0.1"


class FakeIO:
    def __init__(self):
        self.rx, self.tx = [], []
        self.r, self.w = socket.socketpair()
        self.r.setblocking(False)

    def fileno(self):
        return self.r.fileno()

    def inject(self, pkt):
        self.rx.append(pkt)
        self.w.send(b"x")

    def read_packet(self):
        self.r.recv(1)
        return self.rx.pop(0)

    def write_packet(self, pkt):
        self.tx.append(pkt)


def serve(test, kind):
    s = socket.socket(socket.AF_INET, kind)
    test.addCleanup(s.close)
    s.bind(("127.0.0.1", 0))
    if kind == socket.SOCK_STREAM:
        s.listen()
    return s


class ProxyTest(unittest.TestCase):
    def setUp(self):
        self.io = FakeIO()
        self.proxy = Proxy(self.io, ipaddress.ip_network("10.42.0.0/24"))
        self.proxy._forwardable = lambda dst: True
        self.proxy.icmp_sock = None
        self.addCleanup(self.proxy.close)
        self.addCleanup(self.io.r.close)
        self.addCleanup(self.io.w.close)

    def pump(self, until, timeout=3.0):
        end = time.time() + timeout
        while time.time() < end:
            self.proxy.step(0.05)
            hit = until()
            if hit:
                return hit
        self.fail("timed out")

    def tcp_out(self):
        return [pk.parse_tcp(pk.parse_ipv4(p).payload) for p in self.io.tx]

    def test_checksums(self):
        p = pk.build_ipv4("1.2.3.4", "5.6.7.8", 17, b"abcd")
        self.assertEqual(pk.checksum(p[:20]), 0)

    def test_udp_roundtrip(self):
        srv = serve(self, socket.SOCK_DGRAM)
        port = srv.getsockname()[1]
        self.io.inject(pk.build_udp(CLIENT, 5555, SERVER_IP, port, b"ping"))
        threading.Thread(target=lambda: srv.sendto(b"pong", srv.recvfrom(100)[1]), daemon=True).start()
        self.pump(lambda: self.io.tx)
        ip = pk.parse_ipv4(self.io.tx[0])
        dg = pk.parse_udp(ip.payload)
        self.assertEqual(
            (ip.src, ip.dst, dg.sport, dg.dport, dg.payload), (SERVER_IP, CLIENT, port, 5555, b"pong")
        )

    def test_tcp_echo_and_close(self):
        srv = serve(self, socket.SOCK_STREAM)
        port = srv.getsockname()[1]

        def echo():
            c, _ = srv.accept()
            data = b""
            while True:
                d = c.recv(65536)
                if not d:
                    break
                data += d
                c.sendall(d)
            c.close()

        threading.Thread(target=echo, daemon=True).start()

        cseq = 1000
        self.io.inject(pk.build_tcp(CLIENT, 4000, SERVER_IP, port, cseq, 0, pk.SYN))
        synack = self.pump(lambda: [s for s in self.tcp_out() if s.flags == pk.SYN | pk.ACK])[0]
        self.assertEqual(synack.ack, cseq + 1)
        sseq = synack.seq + 1
        cseq += 1
        self.io.inject(pk.build_tcp(CLIENT, 4000, SERVER_IP, port, cseq, sseq, pk.ACK))

        payload = bytes(range(256)) * 40  # 10240 bytes, forces segmentation
        for i in range(0, len(payload), 1400):
            chunk = payload[i : i + 1400]
            self.io.inject(pk.build_tcp(CLIENT, 4000, SERVER_IP, port, cseq, sseq, pk.ACK, payload=chunk))
            cseq += len(chunk)

        def received():
            segs = [s for s in self.tcp_out() if s.payload]
            segs.sort(key=lambda s: s.seq)
            return (
                b"".join(s.payload for s in segs)
                if sum(len(s.payload) for s in segs) >= len(payload)
                else None
            )

        self.assertEqual(self.pump(received), payload)

        self.io.inject(
            pk.build_tcp(CLIENT, 4000, SERVER_IP, port, cseq, sseq + len(payload), pk.ACK | pk.FIN)
        )
        fin = self.pump(lambda: [s for s in self.tcp_out() if s.flags & pk.FIN])[0]
        self.io.inject(pk.build_tcp(CLIENT, 4000, SERVER_IP, port, cseq + 1, fin.seq + 1, pk.ACK))
        self.pump(lambda: not self.proxy.tcp)

    def test_tcp_refused_gets_rst(self):
        s = serve(self, socket.SOCK_STREAM)
        port = s.getsockname()[1]
        s.close()
        self.io.inject(pk.build_tcp(CLIENT, 4001, SERVER_IP, port, 1, 0, pk.SYN))
        self.pump(lambda: [x for x in self.tcp_out() if x.flags & pk.RST])


if __name__ == "__main__":
    unittest.main()
