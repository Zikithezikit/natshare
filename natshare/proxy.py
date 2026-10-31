"""Userspace NAT: terminates client TCP/UDP/ICMP flows and relays them over ordinary sockets."""

import errno
import ipaddress
import logging
import os
import select
import socket
import time
from collections import deque
from typing import Optional

from . import packet as pk

log = logging.getLogger(__name__)

M32 = 0xFFFFFFFF
MSS = 1400
MAX_WINDOW = 65535
UDP_IDLE = 60
TCP_IDLE = 300
ICMP_IDLE = 30
RTO = 1.0

CONNECTING, SYNACKED, ESTABLISHED = range(3)


def _geq(a: int, b: int) -> bool:
    """a >= b in 32-bit sequence space."""
    return (a - b) & M32 < 0x80000000


class TcpFlow:
    def __init__(self, key, sock, client_isn, peer_win):
        self.key, self.sock = key, sock
        self.state = CONNECTING
        self.rcv_nxt = (client_isn + 1) & M32
        self.snd_isn = int.from_bytes(os.urandom(4), "big")
        self.snd_una = self.snd_isn
        self.snd_nxt = (self.snd_isn + 1) & M32
        self.peer_win = peer_win
        self.unacked = deque()  # [seq, data, fin, sent_at]
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
        self.tcp: dict = {}
        self.udp: dict = {}  # (cip, cport, dip, dport) -> [sock, last]
        self.icmp: dict = {}  # (dip, ident) -> [cip, last]
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
            or dst == "255.255.255.255"
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
            flow = self.udp[key] = [s, 0.0]
            log.debug("udp new %s:%d -> %s:%d", *key)
        flow[1] = time.monotonic()
        try:
            flow[0].send(dg.payload)
        except OSError as e:
            log.debug("udp send %s: %s", key, e)

    def _udp_out(self, key, flow) -> None:
        try:
            data = flow[0].recv(65535)
        except OSError:
            return
        flow[1] = time.monotonic()
        cip, cport, dip, dport = key
        if len(data) > 1472:
            log.debug("udp reply too large for MTU (%d bytes), dropped", len(data))
            return
        self._emit(pk.build_udp(dip, dport, cip, cport, data))

    # ---- ICMP ----------------------------------------------------------
    def _icmp_in(self, ip) -> None:
        msg = ip.payload
        if self.icmp_sock is None or len(msg) < 8 or msg[0] != 8:
            return
        ident = int.from_bytes(msg[4:6], "big")
        self.icmp[(ip.dst, ident)] = [ip.src, time.monotonic()]
        try:
            self.icmp_sock.sendto(msg, (ip.dst, 0))
        except OSError as e:
            log.debug("icmp send: %s", e)

    def _icmp_out(self) -> None:
        assert self.icmp_sock is not None
        try:
            raw, _ = self.icmp_sock.recvfrom(65535)
        except OSError:
            return
        ip = pk.parse_ipv4(raw)
        if not ip or ip.proto != pk.ICMP or len(ip.payload) < 8 or ip.payload[0] != 0:
            return
        ident = int.from_bytes(ip.payload[4:6], "big")
        entry = self.icmp.get((ip.src, ident))
        if entry:
            self._emit(pk.build_ipv4(ip.src, entry[0], pk.ICMP, ip.payload))

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
                    seq, data, fin, _ = f.unacked[0]
                    if not _geq(seg.ack, seq + len(data) + fin):
                        break
                    f.unacked.popleft()
        if f.state == CONNECTING:
            return
        payload, seq = seg.payload, seg.seq
        fin = bool(seg.flags & pk.FIN)
        if payload or fin:
            skip = (f.rcv_nxt - seq) & M32
            if 0 < skip < 0x80000000:  # retransmission with new bytes at the tail
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
            data = f.sock.recv(min(max(f.room, 1), 16 * MSS))
        except (BlockingIOError, InterruptedError):
            return
        except OSError:
            self._abort(f)
            return
        now = f.last = time.monotonic()
        if not data:
            f.remote_eof = True
            f.fin_sent = True
            f.unacked.append([f.snd_nxt, b"", True, now])
            self._send(f, f.snd_nxt, pk.FIN | pk.ACK)
            f.snd_nxt = (f.snd_nxt + 1) & M32
            self._maybe_done(f)
            return
        for i in range(0, len(data), MSS):
            chunk = data[i : i + MSS]
            f.unacked.append([f.snd_nxt, chunk, False, now])
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
    def step(self, timeout: float = 0.5) -> None:
        rlist, wlist = [self.io], []
        owners = {}
        if self.icmp_sock:
            rlist.append(self.icmp_sock)
        for key, flow in self.udp.items():
            rlist.append(flow[0])
            owners[flow[0]] = ("udp", key, flow)
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
                for _ in range(128):
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
            elif f.unacked and now - f.unacked[0][3] > RTO:
                e = f.unacked[0]
                e[3] = now
                self._send(f, e[0], pk.ACK | (pk.FIN if e[2] else pk.PSH), e[1])
        for key, flow in list(self.udp.items()):
            if now - flow[1] > UDP_IDLE:
                flow[0].close()
                del self.udp[key]
        for key, entry in list(self.icmp.items()):
            if now - entry[1] > ICMP_IDLE:
                del self.icmp[key]

    def close(self) -> None:
        for f in list(self.tcp.values()):
            f.sock.close()
        for flow in self.udp.values():
            flow[0].close()
        self.tcp.clear()
        self.udp.clear()
        if self.icmp_sock:
            self.icmp_sock.close()
