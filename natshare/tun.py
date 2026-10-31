"""Linux TUN device allocation (/dev/net/tun)."""

import fcntl
import logging
import os
import struct
import subprocess

log = logging.getLogger(__name__)

TUNSETIFF = 0x400454CA
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000


def _prefixlen(netmask: str) -> int:
    return sum(bin(int(o)).count("1") for o in netmask.split("."))


class TunInterface:
    def __init__(self, name: str = "natshare0", ip: str = "10.42.0.1", netmask: str = "255.255.255.0"):
        self.name, self.ip, self.netmask = name, ip, netmask
        self.fd = -1

    def open(self) -> int:
        self.fd = os.open("/dev/net/tun", os.O_RDWR | os.O_NONBLOCK)
        ifr = struct.pack("16sH", self.name.encode(), IFF_TUN | IFF_NO_PI)
        fcntl.ioctl(self.fd, TUNSETIFF, ifr)
        subprocess.run(
            ["ip", "addr", "add", f"{self.ip}/{_prefixlen(self.netmask)}", "dev", self.name], check=True
        )
        subprocess.run(["ip", "link", "set", self.name, "up"], check=True)
        return self.fd

    def fileno(self) -> int:
        return self.fd

    def read_packet(self) -> bytes:
        return os.read(self.fd, 65535)

    def write_packet(self, packet: bytes) -> None:
        os.write(self.fd, packet)

    def close(self) -> None:
        if self.fd >= 0:
            os.close(self.fd)  # non-persistent TUN devices vanish with their last fd
            self.fd = -1
        subprocess.run(["ip", "link", "del", self.name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
