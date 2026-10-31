"""Ephemeral hostapd access point."""

import contextlib
import logging
import os
import subprocess
import time
from typing import Optional

log = logging.getLogger(__name__)

DEFAULT_SSID = "natshare-ap"
DEFAULT_CHANNEL = 6
FIRST_5GHZ_CHANNEL = 36
MIN_PASSPHRASE, MAX_PASSPHRASE = 8, 63
STARTUP_GRACE = 1.5  # seconds to let hostapd fail before assuming it is up
STOP_TIMEOUT = 3
CONF_MODE = 0o600  # config holds the passphrase


def is_wireless(ifname: str) -> bool:
    return os.path.isdir(f"/sys/class/net/{ifname}/wireless") or os.path.isdir(
        f"/sys/class/net/{ifname}/phy80211"
    )


class Hostapd:
    def __init__(
        self,
        iface: str,
        ssid: str = DEFAULT_SSID,
        password: Optional[str] = None,
        channel: int = DEFAULT_CHANNEL,
    ):
        if password is not None and not MIN_PASSPHRASE <= len(password) <= MAX_PASSPHRASE:
            raise ValueError(f"WPA2 passphrase must be {MIN_PASSPHRASE}-{MAX_PASSPHRASE} characters")
        self.iface, self.ssid, self.password, self.channel = iface, ssid, password, channel
        self.conf = f"/tmp/natshare_hostapd_{os.getpid()}.conf"
        self.proc: Optional[subprocess.Popen] = None

    def start(self) -> None:
        subprocess.run(["rfkill", "unblock", "wlan"], check=False)
        lines = [
            f"interface={self.iface}",
            "driver=nl80211",
            f"ssid={self.ssid}",
            f"hw_mode={'a' if self.channel >= FIRST_5GHZ_CHANNEL else 'g'}",
            f"channel={self.channel}",
        ]
        if self.password:
            lines += ["wpa=2", "wpa_key_mgmt=WPA-PSK", "rsn_pairwise=CCMP", f"wpa_passphrase={self.password}"]
        fd = os.open(self.conf, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, CONF_MODE)
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(lines) + "\n")
        self.proc = subprocess.Popen(["hostapd", self.conf])
        time.sleep(STARTUP_GRACE)
        if self.proc.poll() is not None:
            raise RuntimeError("hostapd exited during startup (is the interface managed by NetworkManager?)")

    def alive(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    def stop(self) -> None:
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(STOP_TIMEOUT)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()
        with contextlib.suppress(FileNotFoundError):
            os.unlink(self.conf)
