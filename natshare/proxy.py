"""Userspace NAT: terminates client TCP/UDP/ICMP flows and relays them over ordinary sockets."""

import errno
import ipaddress
import logging
import os
import select
import socket
import time
from collections import deque
from dataclasses import dataclass
from typing import Optional

from . import packet as pk

log = logging.getLogger(__name__)

M32 = pk.SEQ_MASK
SEQ_HALF = pk.SEQ_HALF
MSS = 1400  # advertised to clients; fits a 1500-byte Ethernet MTU with headers to spare
MAX_WINDOW = pk.TCP_MAX_WINDOW
MAX_UDP_REPLY = 1500 - pk.IPV4_HEADER_LEN - pk.UDP_HEADER_LEN  # larger replies would need fragmenting
RECV_SEGMENTS = 16  # max MSS-sized segments read from a remote socket per wakeup
PACKETS_PER_WAKEUP = 128  # max client packets drained per select() wakeup
STEP_TIMEOUT = 0.5  # default select() timeout, seconds
UDP_IDLE = 60  # idle expiry per flow type, seconds
TCP_IDLE = 300
ICMP_IDLE = 30
RTO = 1.0  # fixed retransmission timeout, seconds
BROADCAST = "255.255.255.255"

CONNECTING, SYNACKED, ESTABLISHED = range(3)


def _geq(a: int, b: int) -> bool:
    """a >= b in 32-bit sequence space."""
    return (a - b) & M32 < SEQ_HALF


@dataclass
class Unacked:
    """A segment sent to the client and awaiting acknowledgement."""

    seq: int
    data: bytes
    fin: bool
    sent_at: float


@dataclass
class UdpFlow:
    sock: socket.socket
    last: float


@dataclass
class IcmpEntry:
    client: str
    last: float


class TcpFlow:
    def __init__(self, key, sock, client_isn, peer_win):
        self.key, self.sock = key, sock
        self.state = CONNECTING
        self.rcv_nxt = (client_isn + 1) & M32
        self.snd_isn = int.from_bytes(os.urandom(4), "big")
        self.snd_una = self.snd_isn
        self.snd_nxt = (self.snd_isn + 1) & M32
        self.peer_win = peer_win
        self.unacked: deque[Unacked] = deque()
        self.out_buf = bytearray()  # client -> remote, not yet written to the socket
        self.client_fin = False
        self.shut_wr = False
        self.remote_eof = False
        self.fin_sent = False
        self.synack_at = 0.0
        self.last = time.monotonic()

    @property
    def inflight(self) -> int:
        return (self.snd_nxt - self.snd_una) & M32

    @property
    def room(self) -> int:
        return min(self.peer_win, MAX_WINDOW) - self.inflight


class Proxy:
    def __init__(self, io, subnet: ipaddress.IPv4Network, wan: Optional[str] = None):
        self.io, self.subnet, self.wan = io, subnet, wan
        self.tcp: dict[tuple[str, int, str, int], TcpFlow] = {}
        self.udp: dict[tuple[str, int, str, int], UdpFlow] = {}  # (cip, cport, dip, dport)
        self.icmp: dict[tuple[str, int], IcmpEntry] = {}  # (dip, ident)
        self.icmp_sock: Optional[socket.socket] = None
        try:
            self.icmp_sock = self._sock(socket.SOCK_RAW, socket.IPPROTO_ICMP)
        except OSError as e:
            log.warning("ICMP relay disabled: %s", e)

    # ---- helpers -------------------------------------------------------
    def _sock(self, kind, proto=0):
        s = socket.socket(socket.AF_INET, kind, proto)
        s.setblocking(False)
        if self.wan:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, self.wan.encode())
        return s

    def _emit(self, pkt: bytes) -> None:
        try:
            self.io.write_packet(pkt)
        except OSError as e:
            log.debug("write to client failed: %s", e)

    def _forwardable(self, dst: str) -> bool:
        addr = ipaddress.IPv4Address(dst)
        return not (
            addr in self.subnet
            or addr.is_multicast
            or addr.is_loopback
            or addr.is_unspecified
            or dst == BROADCAST
        )

    # ---- packet ingress ------------------------------------------------
    def handle_packet(self, raw: bytes) -> None:
        ip = pk.parse_ipv4(raw)
        if ip is None or ipaddress.IPv4Address(ip.src) not in self.subnet or not self._forwardable(ip.dst):
            return
        if ip.proto == pk.TCP:
            seg = pk.parse_tcp(ip.payload)
            if seg:
                self._tcp_in(ip, seg)
        elif ip.proto == pk.UDP:
            dg = pk.parse_udp(ip.payload)
            if dg:
                self._udp_in(ip, dg)
        elif ip.proto == pk.ICMP:
            self._icmp_in(ip)

    # ---- UDP -----------------------------------------------------------
    def _udp_in(self, ip, dg) -> None:
        key = (ip.src, dg.sport, ip.dst, dg.dport)
        flow = self.udp.get(key)
        if flow is None:
            try:
                s = self._sock(socket.SOCK_DGRAM)
                s.connect((ip.dst, dg.dport))
            except OSError as e:
                log.debug("udp %s: %s", key, e)
                return
            flow = self.udp[key] = UdpFlow(s, 0.0)
            log.debug("udp new %s:%d -> %s:%d", *key)
        flow.last = time.monotonic()
        try:
            flow.sock.send(dg.payload)
        except OSError as e:
            log.debug("udp send %s: %s", key, e)

    def _udp_out(self, key, flow) -> None:
        try:
            data = flow.sock.recv(pk.IPV4_MAX_PACKET)
        except OSError:
            return
        flow.last = time.monotonic()
        cip, cport, dip, dport = key
        if len(data) > MAX_UDP_REPLY:
            log.debug("udp reply too large for MTU (%d bytes), dropped", len(data))
            return
        self._emit(pk.build_udp(dip, dport, cip, cport, data))

    # ---- ICMP ----------------------------------------------------------
    def _icmp_in(self, ip) -> None:
        msg = ip.payload
        if self.icmp_sock is None or len(msg) < pk.ICMP_HEADER_LEN or msg[0] != pk.ICMP_ECHO_REQUEST:
            return
        ident = int.from_bytes(msg[pk.ICMP_ID_OFFSET : pk.ICMP_ID_END], "big")
        self.icmp[(ip.dst, ident)] = IcmpEntry(ip.src, time.monotonic())
        try:
            self.icmp_sock.sendto(msg, (ip.dst, 0))
        except OSError as e:
            log.debug("icmp send: %s", e)

    def _icmp_out(self) -> None:
        assert self.icmp_sock is not None
        try:
            raw, _ = self.icmp_sock.recvfrom(pk.IPV4_MAX_PACKET)
        except OSError:
            return
        ip = pk.parse_ipv4(raw)
        if (
            not ip
            or ip.proto != pk.ICMP
            or len(ip.payload) < pk.ICMP_HEADER_LEN
            or ip.payload[0] != pk.ICMP_ECHO_REPLY
        ):
            return
        ident = int.from_bytes(ip.payload[pk.ICMP_ID_OFFSET : pk.ICMP_ID_END], "big")
        entry = self.icmp.get((ip.src, ident))
        if entry:
            self._emit(pk.build_ipv4(ip.src, entry.client, pk.ICMP, ip.payload))

    # ---- TCP -----------------------------------------------------------
    def _send(self, f, seq, flags, payload=b"", mss=None, ack=None) -> None:
        cip, cport, dip, dport = f.key
        win = max(0, MAX_WINDOW - len(f.out_buf))
        self._emit(
            pk.build_tcp(
                dip, dport, cip, cport, seq, f.rcv_nxt if ack is None else ack, flags, win, payload, mss
            )
        )

    def _rst_for(self, ip, seg) -> None:
        if seg.flags & pk.ACK:
            out = pk.build_tcp(ip.dst, seg.dport, ip.src, seg.sport, seg.ack, 0, pk.RST, 0)
        else:
            n = len(seg.payload) + bool(seg.flags & pk.SYN) + bool(seg.flags & pk.FIN)
            out = pk.build_tcp(
                ip.dst, seg.dport, ip.src, seg.sport, 0, (seg.seq + n) & M32, pk.RST | pk.ACK, 0
            )
        self._emit(out)

    def _tcp_in(self, ip, seg) -> None:
        key = (ip.src, seg.sport, ip.dst, seg.dport)
        f = self.tcp.get(key)
        if seg.flags & pk.SYN and not seg.flags & pk.ACK:
            if f:
                if f.state == SYNACKED:
                    self._send_synack(f)
                return
            try:
                s = self._sock(socket.SOCK_STREAM)
                s.connect_ex((ip.dst, seg.dport))
            except OSError as e:
                log.debug("tcp connect %s: %s", key, e)
                self._rst_for(ip, seg)
                return
            self.tcp[key] = TcpFlow(key, s, seg.seq, seg.window)
            log.debug("tcp new %s:%d -> %s:%d", *key)
            return
        if f is None:
            if not seg.flags & pk.RST:
                self._rst_for(ip, seg)
            return
        if seg.flags & pk.RST:
            self._close(f)
            return
        f.last = time.monotonic()
        if seg.flags & pk.ACK:
            f.peer_win = seg.window
            if f.state == SYNACKED and _geq(seg.ack, f.snd_isn + 1):
                f.state = ESTABLISHED
            outstanding = f.inflight
            if 0 < (seg.ack - f.snd_una) & M32 <= outstanding:
                f.snd_una = seg.ack
                while f.unacked:
                    head = f.unacked[0]
                    if not _geq(seg.ack, head.seq + len(head.data) + head.fin):
                        break
                    f.unacked.popleft()
        if f.state == CONNECTING:
            return
        payload, seq = seg.payload, seg.seq
        fin = bool(seg.flags & pk.FIN)
        if payload or fin:
            skip = (f.rcv_nxt - seq) & M32
            if 0 < skip < SEQ_HALF:  # retransmission with new bytes at the tail
                payload, seq = payload[skip:], f.rcv_nxt
            if seq == f.rcv_nxt:
                f.out_buf += payload
                f.rcv_nxt = (f.rcv_nxt + len(payload)) & M32
                if fin and not f.client_fin:
                    f.client_fin = True
                    f.rcv_nxt = (f.rcv_nxt + 1) & M32
            self._send(f, f.snd_nxt, pk.ACK)
            self._flush_remote(f)
        self._maybe_done(f)

    def _send_synack(self, f) -> None:
        f.synack_at = time.monotonic()
        self._send(f, f.snd_isn, pk.SYN | pk.ACK, mss=MSS)

    def _flush_remote(self, f) -> None:
        try:
            if f.out_buf:
                n = f.sock.send(f.out_buf)
                del f.out_buf[:n]
            if not f.out_buf and f.client_fin and not f.shut_wr:
                f.sock.shutdown(socket.SHUT_WR)
                f.shut_wr = True
        except (BlockingIOError, InterruptedError):
            pass
        except OSError:
            self._abort(f)

    def _remote_readable(self, f) -> None:
        try:
            data = f.sock.recv(min(max(f.room, 1), RECV_SEGMENTS * MSS))
        except (BlockingIOError, InterruptedError):
            return
        except OSError:
            self._abort(f)
            return
        now = f.last = time.monotonic()
        if not data:
            f.remote_eof = True
            f.fin_sent = True
            f.unacked.append(Unacked(f.snd_nxt, b"", True, now))
            self._send(f, f.snd_nxt, pk.FIN | pk.ACK)
            f.snd_nxt = (f.snd_nxt + 1) & M32
            self._maybe_done(f)
            return
        for i in range(0, len(data), MSS):
            chunk = data[i : i + MSS]
            f.unacked.append(Unacked(f.snd_nxt, chunk, False, now))
            self._send(f, f.snd_nxt, pk.ACK | pk.PSH, chunk)
            f.snd_nxt = (f.snd_nxt + len(chunk)) & M32

    def _connect_done(self, f) -> None:
        err = f.sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
        if err:
            log.debug("tcp connect %s failed: %s", f.key, errno.errorcode.get(err, err))
            self._send(f, 0, pk.RST | pk.ACK)
            self._close(f)
            return
        f.state = SYNACKED
        self._send_synack(f)

    def _abort(self, f) -> None:
        self._send(f, f.snd_nxt, pk.RST | pk.ACK)
        self._close(f)

    def _maybe_done(self, f) -> None:
        if f.client_fin and f.fin_sent and not f.unacked and not f.out_buf:
            self._close(f)

    def _close(self, f) -> None:
        self.tcp.pop(f.key, None)
        f.sock.close()

    # ---- event loop ----------------------------------------------------
    def step(self, timeout: float = STEP_TIMEOUT) -> None:
        rlist: list = [self.io]
        wlist: list = []
        owners: dict = {}
        if self.icmp_sock:
            rlist.append(self.icmp_sock)
        for key, flow in self.udp.items():
            rlist.append(flow.sock)
            owners[flow.sock] = ("udp", key, flow)
        for f in self.tcp.values():
            owners[f.sock] = ("tcp", f.key, f)
            if f.state == CONNECTING:
                wlist.append(f.sock)
                continue
            if f.out_buf:
                wlist.append(f.sock)
            if not f.remote_eof and f.state == ESTABLISHED and f.room > 0:
                rlist.append(f.sock)
        r, w, _ = select.select(rlist, wlist, [], timeout)
        for s in w:
            f = owners[s][2]
            if f.state == CONNECTING:
                self._connect_done(f)
            elif f.key in self.tcp:
                self._flush_remote(f)
                self._maybe_done(f)
        for s in r:
            if s is self.io:
                for _ in range(PACKETS_PER_WAKEUP):
                    try:
                        raw = self.io.read_packet()
                    except (BlockingIOError, InterruptedError):
                        break
                    if raw:
                        self.handle_packet(raw)
            elif s is self.icmp_sock:
                self._icmp_out()
            else:
                kind, key, flow = owners[s]
                if kind == "udp":
                    self._udp_out(key, flow)
                elif key in self.tcp:
                    self._remote_readable(flow)
        self._timers()

    def _timers(self) -> None:
        now = time.monotonic()
        for f in list(self.tcp.values()):
            if now - f.last > TCP_IDLE:
                self._abort(f)
            elif f.state == SYNACKED and now - f.synack_at > RTO:
                self._send_synack(f)
            elif f.unacked and now - f.unacked[0].sent_at > RTO:
                e = f.unacked[0]
                e.sent_at = now
                self._send(f, e.seq, pk.ACK | (pk.FIN if e.fin else pk.PSH), e.data)
        for ukey, uflow in list(self.udp.items()):
            if now - uflow.last > UDP_IDLE:
                uflow.sock.close()
                del self.udp[ukey]
        for ikey, entry in list(self.icmp.items()):
            if now - entry.last > ICMP_IDLE:
                del self.icmp[ikey]

    def close(self) -> None:
        for f in list(self.tcp.values()):
            f.sock.close()
        for flow in self.udp.values():
            flow.sock.close()
        self.tcp.clear()
        self.udp.clear()
        if self.icmp_sock:
            self.icmp_sock.close()
