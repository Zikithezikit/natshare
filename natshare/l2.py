"""Client-facing packet source: IPv4 over Ethernet on the LAN interface.

Uses an AF_PACKET socket, so client traffic reaches userspace without the
kernel having to forward it (no ip_forward, no iptables).  ARP for the
gateway address is answered by the kernel, since the LAN interface holds it.
"""

import socket
import struct

from . import packet as pk

ETH_P_IP = 0x0800
ETH_HEADER_LEN = 14
MAC_LEN = 6
ETH_SRC = slice(MAC_LEN, 2 * MAC_LEN)
PACKET_OUTGOING = 4  # sockaddr_ll pkttype
PKTTYPE_INDEX = 2  # position of pkttype in the recvfrom() address tuple
IPV4_SRC = slice(12, 12 + pk.IPV4_ADDR_LEN)
IPV4_DST = slice(16, 16 + pk.IPV4_ADDR_LEN)


class L2Port:
    def __init__(self, ifname: str):
        self.ifname = ifname
        self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_IP))
        self.sock.bind((ifname, ETH_P_IP))
        self.sock.setblocking(False)
        with open(f"/sys/class/net/{ifname}/address") as f:
            self.mac = bytes.fromhex(f.read().strip().replace(":", ""))
        self.macs: dict[str, bytes] = {}  # client ip -> mac, learned from received frames

    def fileno(self) -> int:
        return self.sock.fileno()

    def read_packet(self):
        """Returns one IPv4 packet, or None for frames to ignore. Raises BlockingIOError when drained."""
        frame, addr = self.sock.recvfrom(pk.IPV4_MAX_PACKET)
        too_short = len(frame) < ETH_HEADER_LEN + pk.IPV4_HEADER_LEN
        if addr[PKTTYPE_INDEX] == PACKET_OUTGOING or too_short or frame[ETH_SRC] == self.mac:
            return None
        pkt = frame[ETH_HEADER_LEN:]
        self.macs[socket.inet_ntoa(pkt[IPV4_SRC])] = frame[ETH_SRC]
        return pkt

    def write_packet(self, packet: bytes) -> None:
        mac = self.macs.get(socket.inet_ntoa(packet[IPV4_DST]))
        if mac:
            self.sock.send(mac + self.mac + struct.pack("!H", ETH_P_IP) + packet)

    def close(self) -> None:
        self.sock.close()
