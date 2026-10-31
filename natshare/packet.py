"""IPv4/TCP/UDP/ICMP packet parsing and construction."""

import itertools
import socket
import struct
from dataclasses import dataclass

TCP, UDP, ICMP = 6, 17, 1
FIN, SYN, RST, PSH, ACK = 0x01, 0x02, 0x04, 0x08, 0x10

_ids = itertools.count(1)


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


@dataclass
class IPv4:
    src: str
    dst: str
    proto: int
    payload: bytes
    ttl: int = 64


@dataclass
class TCPSegment:
    sport: int
    dport: int
    seq: int
    ack: int
    flags: int
    window: int
    payload: bytes


@dataclass
class UDPDatagram:
    sport: int
    dport: int
    payload: bytes


def parse_ipv4(pkt: bytes):
    """Returns an IPv4, or None for non-IPv4, malformed or fragmented packets."""
    if len(pkt) < 20 or pkt[0] >> 4 != 4:
        return None
    ihl = (pkt[0] & 0x0F) * 4
    total = struct.unpack("!H", pkt[2:4])[0]
    if ihl < 20 or total < ihl or total > len(pkt):
        return None
    if struct.unpack("!H", pkt[6:8])[0] & 0x3FFF:  # MF flag or fragment offset
        return None
    return IPv4(socket.inet_ntoa(pkt[12:16]), socket.inet_ntoa(pkt[16:20]), pkt[9], pkt[ihl:total], pkt[8])


def parse_tcp(data: bytes):
    if len(data) < 20:
        return None
    sport, dport, seq, ack, off, flags, win = struct.unpack("!HHIIBBH", data[:16])
    off = (off >> 4) * 4
    if off < 20 or off > len(data):
        return None
    return TCPSegment(sport, dport, seq, ack, flags, win, data[off:])


def parse_udp(data: bytes):
    if len(data) < 8:
        return None
    sport, dport, length = struct.unpack("!HHH", data[:6])
    if length < 8 or length > len(data):
        return None
    return UDPDatagram(sport, dport, data[8:length])


def build_ipv4(src: str, dst: str, proto: int, payload: bytes) -> bytes:
    hdr = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(payload),
        next(_ids) & 0xFFFF,
        0x4000,
        64,
        proto,
        0,
        socket.inet_aton(src),
        socket.inet_aton(dst),
    )
    return hdr[:10] + struct.pack("!H", checksum(hdr)) + hdr[12:] + payload


def _pseudo(src: str, dst: str, proto: int, length: int) -> bytes:
    return socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack("!BBH", 0, proto, length)


def build_tcp(src, sport, dst, dport, seq, ack, flags, window=65535, payload=b"", mss=None) -> bytes:
    opts = struct.pack("!BBH", 2, 4, mss) if mss else b""
    hdr = (
        struct.pack(
            "!HHIIBBHHH",
            sport,
            dport,
            seq & 0xFFFFFFFF,
            ack & 0xFFFFFFFF,
            ((20 + len(opts)) // 4) << 4,
            flags,
            window,
            0,
            0,
        )
        + opts
    )
    seg = hdr + payload
    csum = checksum(_pseudo(src, dst, TCP, len(seg)) + seg)
    seg = seg[:16] + struct.pack("!H", csum) + seg[18:]
    return build_ipv4(src, dst, TCP, seg)


def build_udp(src, sport, dst, dport, payload: bytes) -> bytes:
    seg = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    csum = checksum(_pseudo(src, dst, UDP, len(seg)) + seg) or 0xFFFF
    seg = seg[:6] + struct.pack("!H", csum) + seg[8:]
    return build_ipv4(src, dst, UDP, seg)


def build_icmp_echo(src, dst, ident, seq, data: bytes, reply=False) -> bytes:
    msg = struct.pack("!BBHHH", 0 if reply else 8, 0, 0, ident, seq) + data
    msg = msg[:2] + struct.pack("!H", checksum(msg)) + msg[4:]
    return build_ipv4(src, dst, ICMP, msg)
