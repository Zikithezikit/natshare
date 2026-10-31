"""IPv4/TCP/UDP/ICMP packet parsing and construction."""

import itertools
import socket
import struct
from dataclasses import dataclass
from typing import Optional

# IP protocol numbers
ICMP, TCP, UDP = 1, 6, 17

# TCP flags
FIN, SYN, RST, PSH, ACK = 0x01, 0x02, 0x04, 0x08, 0x10

# ICMP echo types
ICMP_ECHO_REPLY, ICMP_ECHO_REQUEST = 0, 8

IPV4_VERSION = 4
IPV4_HEADER_LEN = 20
IPV4_VER_IHL = (IPV4_VERSION << 4) | (IPV4_HEADER_LEN // 4)
IPV4_DF = 0x4000
IPV4_FRAG_MASK = 0x3FFF  # MF flag | fragment offset
IPV4_DEFAULT_TTL = 64
IPV4_MAX_PACKET = 65535
_IPV4_HEADER = struct.Struct("!BBHHHBBH4s4s")
_IPV4_CSUM_OFFSET = 10
IPV4_ADDR_LEN = 4

TCP_HEADER_LEN = 20
TCP_MAX_WINDOW = 65535
TCP_OPT_MSS, TCP_OPT_MSS_LEN = 2, 4
_TCP_HEADER = struct.Struct("!HHIIBBHHH")
_TCP_CSUM_OFFSET = 16

UDP_HEADER_LEN = 8
_UDP_HEADER = struct.Struct("!HHHH")
_UDP_CSUM_OFFSET = 6

ICMP_HEADER_LEN = 8
_ICMP_ECHO_HEADER = struct.Struct("!BBHHH")
_ICMP_CSUM_OFFSET = 2
ICMP_ID_OFFSET = 4
ICMP_ID_END = ICMP_ID_OFFSET + 2

WORD_BITS, WORD_MASK = 16, 0xFFFF  # checksum / IP id arithmetic is on 16-bit words
IHL_MASK, IHL_UNIT = 0x0F, 4  # IPv4 header length field counts 32-bit words
SEQ_MASK = 0xFFFFFFFF
SEQ_HALF = 0x80000000

_ids = itertools.count(1)


def checksum(data: bytes) -> int:
    """RFC 1071 Internet checksum."""
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> WORD_BITS:
        total = (total & WORD_MASK) + (total >> WORD_BITS)
    return ~total & WORD_MASK


def _set_checksum(data: bytes, offset: int) -> bytes:
    return data[:offset] + struct.pack("!H", checksum(data)) + data[offset + 2 :]


@dataclass
class IPv4:
    src: str
    dst: str
    proto: int
    payload: bytes
    ttl: int = IPV4_DEFAULT_TTL


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


def parse_ipv4(pkt: bytes) -> Optional[IPv4]:
    """Returns an IPv4, or None for non-IPv4, malformed or fragmented packets."""
    if len(pkt) < IPV4_HEADER_LEN or pkt[0] >> 4 != IPV4_VERSION:
        return None
    ihl = (pkt[0] & IHL_MASK) * IHL_UNIT
    _, _, total, _, frag, ttl, proto, _, src, dst = _IPV4_HEADER.unpack(pkt[:IPV4_HEADER_LEN])
    if ihl < IPV4_HEADER_LEN or total < ihl or total > len(pkt) or frag & IPV4_FRAG_MASK:
        return None
    return IPv4(socket.inet_ntoa(src), socket.inet_ntoa(dst), proto, pkt[ihl:total], ttl)


def parse_tcp(data: bytes) -> Optional[TCPSegment]:
    if len(data) < TCP_HEADER_LEN:
        return None
    sport, dport, seq, ack, off, flags, win, _, _ = _TCP_HEADER.unpack(data[:TCP_HEADER_LEN])
    off = (off >> 4) * 4
    if off < TCP_HEADER_LEN or off > len(data):
        return None
    return TCPSegment(sport, dport, seq, ack, flags, win, data[off:])


def parse_udp(data: bytes) -> Optional[UDPDatagram]:
    if len(data) < UDP_HEADER_LEN:
        return None
    sport, dport, length, _ = _UDP_HEADER.unpack(data[:UDP_HEADER_LEN])
    if length < UDP_HEADER_LEN or length > len(data):
        return None
    return UDPDatagram(sport, dport, data[UDP_HEADER_LEN:length])


def build_ipv4(src: str, dst: str, proto: int, payload: bytes) -> bytes:
    hdr = _IPV4_HEADER.pack(
        IPV4_VER_IHL,
        0,
        IPV4_HEADER_LEN + len(payload),
        next(_ids) & WORD_MASK,
        IPV4_DF,
        IPV4_DEFAULT_TTL,
        proto,
        0,
        socket.inet_aton(src),
        socket.inet_aton(dst),
    )
    return _set_checksum(hdr, _IPV4_CSUM_OFFSET) + payload


def _pseudo(src: str, dst: str, proto: int, length: int) -> bytes:
    return socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack("!BBH", 0, proto, length)


def build_tcp(
    src: str,
    sport: int,
    dst: str,
    dport: int,
    seq: int,
    ack: int,
    flags: int,
    window: int = TCP_MAX_WINDOW,
    payload: bytes = b"",
    mss: Optional[int] = None,
) -> bytes:
    opts = struct.pack("!BBH", TCP_OPT_MSS, TCP_OPT_MSS_LEN, mss) if mss else b""
    hdr = _TCP_HEADER.pack(
        sport,
        dport,
        seq & SEQ_MASK,
        ack & SEQ_MASK,
        ((TCP_HEADER_LEN + len(opts)) // 4) << 4,
        flags,
        window,
        0,
        0,
    )
    seg = hdr + opts + payload
    csum = checksum(_pseudo(src, dst, TCP, len(seg)) + seg)
    seg = seg[:_TCP_CSUM_OFFSET] + struct.pack("!H", csum) + seg[_TCP_CSUM_OFFSET + 2 :]
    return build_ipv4(src, dst, TCP, seg)


def build_udp(src: str, sport: int, dst: str, dport: int, payload: bytes) -> bytes:
    seg = _UDP_HEADER.pack(sport, dport, UDP_HEADER_LEN + len(payload), 0) + payload
    csum = checksum(_pseudo(src, dst, UDP, len(seg)) + seg) or WORD_MASK  # 0 means "no checksum"
    seg = seg[:_UDP_CSUM_OFFSET] + struct.pack("!H", csum) + seg[_UDP_CSUM_OFFSET + 2 :]
    return build_ipv4(src, dst, UDP, seg)


def build_icmp_echo(src: str, dst: str, ident: int, seq: int, data: bytes, reply: bool = False) -> bytes:
    kind = ICMP_ECHO_REPLY if reply else ICMP_ECHO_REQUEST
    msg = _set_checksum(_ICMP_ECHO_HEADER.pack(kind, 0, 0, ident, seq) + data, _ICMP_CSUM_OFFSET)
    return build_ipv4(src, dst, ICMP, msg)
