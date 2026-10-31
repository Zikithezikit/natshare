"""Orchestration: setup, event loop and guaranteed cleanup."""

import ipaddress
import logging
import os
import shutil
import signal
import subprocess
import sys
from dataclasses import dataclass
from typing import Optional

from .dhcp import Dnsmasq
from .l2 import L2Port
from .netconst import DEFAULT_SUBNET, GATEWAY_OFFSET, MAX_PREFIXLEN
from .proxy import Proxy
from .wifi import DEFAULT_SSID, Hostapd, is_wireless

log = logging.getLogger(__name__)

LOOP_INTERVAL = 0.5  # seconds between supervision checks of child processes


@dataclass
class Config:
    wan: str
    lan: str
    ssid: Optional[str] = None
    password: Optional[str] = None
    subnet: str = DEFAULT_SUBNET
    verbose: bool = False


def _ip(*args: str, check: bool = True) -> None:
    subprocess.run(["ip", *args], check=check, stdout=subprocess.DEVNULL)


def _link_is_up(ifname: str) -> bool:
    out = subprocess.run(["ip", "-o", "link", "show", ifname], capture_output=True, text=True).stdout
    return "<" in out and "UP" in out.split("<", 1)[1].split(">", 1)[0].split(",")


class NatShare:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.stop = False
        self.net = ipaddress.IPv4Network(cfg.subnet, strict=False)  # raises ValueError if invalid
        self.gateway = self.net.network_address + GATEWAY_OFFSET
        self.hostapd: Optional[Hostapd] = None
        self.dnsmasq: Optional[Dnsmasq] = None
        self.port: Optional[L2Port] = None
        self.proxy: Optional[Proxy] = None
        self.addr_added = False
        self.was_up = True

    def _check(self) -> Optional[str]:
        """Returns an error message if the environment is unusable, else None."""
        if os.geteuid() != 0:
            return "natshare must be run as root (needs CAP_NET_ADMIN / CAP_NET_RAW)"
        if self.net.prefixlen > MAX_PREFIXLEN:
            return f"subnet {self.cfg.subnet} must be an IPv4 network of /{MAX_PREFIXLEN} or larger"
        for ifname in (self.cfg.wan, self.cfg.lan):
            if not os.path.isdir(f"/sys/class/net/{ifname}"):
                return f"interface {ifname!r} does not exist"
        if self.cfg.wan == self.cfg.lan:
            return "--wan and --lan must be different interfaces"
        need = ["ip", "dnsmasq"] + (["hostapd"] if is_wireless(self.cfg.lan) else [])
        missing = [b for b in need if not shutil.which(b)]
        if missing:
            return "missing required binaries: " + ", ".join(missing)
        return None

    def run(self) -> int:
        err = self._check()
        if err:
            print(f"natshare: {err}", file=sys.stderr)
            return 1
        for sig in (signal.SIGINT, signal.SIGTERM):
            signal.signal(sig, lambda *_: setattr(self, "stop", True))
        try:
            self._setup()
            log.info(
                "sharing %s -> %s on %s (gateway %s); Ctrl-C to stop",
                self.cfg.wan,
                self.cfg.lan,
                self.net,
                self.gateway,
            )
            while not self.stop:
                assert self.proxy is not None
                self.proxy.step(LOOP_INTERVAL)
                if self.dnsmasq and not self.dnsmasq.alive():
                    raise RuntimeError("dnsmasq exited unexpectedly (is another DNS server using port 53?)")
                if self.hostapd and not self.hostapd.alive():
                    raise RuntimeError("hostapd exited unexpectedly")
            return 0
        except Exception as e:
            log.error("%s", e)
            return 1
        finally:
            self._cleanup()

    def _setup(self) -> None:
        cfg = self.cfg
        if is_wireless(cfg.lan):
            self.hostapd = Hostapd(cfg.lan, cfg.ssid or DEFAULT_SSID, cfg.password)
            self.hostapd.start()
        elif cfg.ssid or cfg.password:
            log.warning("%s is not wireless; ignoring --ssid/--password", cfg.lan)
        self.was_up = _link_is_up(cfg.lan)
        _ip("addr", "add", f"{self.gateway}/{self.net.prefixlen}", "dev", cfg.lan)
        self.addr_added = True
        _ip("link", "set", cfg.lan, "up")
        self.dnsmasq = Dnsmasq(cfg.lan, self.net, cfg.verbose)
        self.dnsmasq.start()
        self.port = L2Port(cfg.lan)
        self.proxy = Proxy(self.port, self.net, cfg.wan)

    def _cleanup(self) -> None:
        log.info("cleaning up")
        lan, cidr = self.cfg.lan, f"{self.gateway}/{self.net.prefixlen}"

        def release_lan() -> None:
            if self.addr_added:
                _ip("addr", "del", cidr, "dev", lan, check=False)
            if not self.was_up:
                _ip("link", "set", lan, "down", check=False)

        steps = [
            self.hostapd.stop if self.hostapd else None,
            self.dnsmasq.stop if self.dnsmasq else None,
            self.proxy.close if self.proxy else None,
            self.port.close if self.port else None,
            release_lan,
        ]
        for step in steps:
            if step is None:
                continue
            try:
                step()
            except Exception as e:  # keep tearing down whatever remains
                log.warning("cleanup step failed: %s", e)
