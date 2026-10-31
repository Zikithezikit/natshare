"""Client-facing packet source: IPv4 over Ethernet on the LAN interface.

Uses an AF_PACKET socket, so client traffic reaches userspace without the
kernel having to forward it (no ip_forward, no iptables).  ARP for the
gateway address is answered by the kernel, since the LAN interface holds it.
"""

import socket
import struct

ETH_P_IP = 0x0800
PACKET_OUTGOING = 4


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
        frame, addr = self.sock.recvfrom(65535)
        if addr[2] == PACKET_OUTGOING or len(frame) < 34 or frame[6:12] == self.mac:
            return None
        pkt = frame[14:]
        self.macs[socket.inet_ntoa(pkt[12:16])] = frame[6:12]
        return pkt

    def write_packet(self, packet: bytes) -> None:
        mac = self.macs.get(socket.inet_ntoa(packet[16:20]))
        if mac:
            self.sock.send(mac + self.mac + struct.pack("!H", ETH_P_IP) + packet)

    def close(self) -> None:
        self.sock.close()
