"""Ephemeral hostapd access point."""

import contextlib
import logging
import os
import subprocess
import time
from typing import Optional

log = logging.getLogger(__name__)


def is_wireless(ifname: str) -> bool:
    return os.path.isdir(f"/sys/class/net/{ifname}/wireless") or os.path.isdir(
        f"/sys/class/net/{ifname}/phy80211"
    )


class Hostapd:
    def __init__(self, iface: str, ssid: str = "natshare-ap", password=None, channel: int = 6):
        if password is not None and not 8 <= len(password) <= 63:
            raise ValueError("WPA2 passphrase must be 8-63 characters")
        self.iface, self.ssid, self.password, self.channel = iface, ssid, password, channel
        self.conf = f"/tmp/natshare_hostapd_{os.getpid()}.conf"
        self.proc: Optional[subprocess.Popen] = None

    def start(self) -> None:
        subprocess.run(["rfkill", "unblock", "wlan"], check=False)
        lines = [
            f"interface={self.iface}",
            "driver=nl80211",
            f"ssid={self.ssid}",
            f"hw_mode={'a' if self.channel >= 36 else 'g'}",
            f"channel={self.channel}",
        ]
        if self.password:
            lines += ["wpa=2", "wpa_key_mgmt=WPA-PSK", "rsn_pairwise=CCMP", f"wpa_passphrase={self.password}"]
        fd = os.open(self.conf, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)  # holds the passphrase
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(lines) + "\n")
        self.proc = subprocess.Popen(["hostapd", self.conf])
        time.sleep(1.5)
        if self.proc.poll() is not None:
            raise RuntimeError("hostapd exited during startup (is the interface managed by NetworkManager?)")

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
        with contextlib.suppress(FileNotFoundError):
            os.unlink(self.conf)
