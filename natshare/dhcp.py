"""Ephemeral dnsmasq instance bound to the LAN interface."""

import contextlib
import ipaddress
import logging
import os
import subprocess
from typing import Optional

log = logging.getLogger(__name__)


class Dnsmasq:
    def __init__(self, lan: str, subnet: ipaddress.IPv4Network, verbose: bool = False):
        self.lan, self.subnet, self.verbose = lan, subnet, verbose
        self.gateway = subnet.network_address + 1
        last = subnet.broadcast_address - 1
        self.range = (subnet.network_address + 10, min(subnet.network_address + 100, last))
        self.conf = f"/tmp/natshare_dnsmasq_{os.getpid()}.conf"
        self.leases = f"/tmp/natshare_dnsmasq_{os.getpid()}.leases"
        self.proc: Optional[subprocess.Popen] = None

    def start(self) -> None:
        lines = [
            f"interface={self.lan}",
            "bind-interfaces",
            f"dhcp-range={self.range[0]},{self.range[1]},{self.subnet.netmask},12h",
            f"dhcp-option=option:router,{self.gateway}",
            f"dhcp-option=option:dns-server,{self.gateway}",
            "port=53",
            f"dhcp-leasefile={self.leases}",
            f"pid-file={self.conf}.pid",
        ]
        if self.verbose:
            lines += ["log-dhcp", "log-queries"]
        with open(self.conf, "w") as f:
            f.write("\n".join(lines) + "\n")
        self.proc = subprocess.Popen(["dnsmasq", "--keep-in-foreground", f"--conf-file={self.conf}"])
        log.debug("dnsmasq started (pid %d), config %s", self.proc.pid, self.conf)

    def alive(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    def stop(self) -> None:
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(3)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()
        for path in (self.conf, self.leases, self.conf + ".pid"):
            with contextlib.suppress(FileNotFoundError):
                os.unlink(path)
