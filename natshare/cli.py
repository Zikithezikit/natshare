import argparse
import logging
from collections.abc import Sequence
from typing import Optional

from . import __version__
from .core import Config, NatShare
from .netconst import DEFAULT_SUBNET


def main(argv: Optional[Sequence[str]] = None) -> int:
    p = argparse.ArgumentParser(
        prog="natshare", description="Transient Userspace Internet Connection Sharing Tool"
    )
    p.add_argument("--wan", "-w", required=True, help="WAN interface connected to internet (e.g., eth1)")
    p.add_argument(
        "--lan", "-l", required=True, help="LAN interface to share connection to (e.g., wlan0, eth2)"
    )
    p.add_argument(
        "--ssid",
        "-s",
        help="SSID for Wi-Fi access point (activates hostapd if LAN is wireless; default natshare-ap)",
    )
    p.add_argument(
        "--password", "-p", help="WPA2 passphrase for Wi-Fi access point (open network if omitted)"
    )
    p.add_argument(
        "--subnet", default=DEFAULT_SUBNET, help=f"Subnet for local clients (default: {DEFAULT_SUBNET})"
    )
    p.add_argument("--verbose", "-v", action="store_true", help="Enable debug logging output")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    a = p.parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if a.verbose else logging.INFO, format="%(asctime)s %(levelname)s %(message)s"
    )
    try:
        app = NatShare(Config(a.wan, a.lan, a.ssid, a.password, a.subnet, a.verbose))
    except ValueError as e:
        p.error(f"invalid --subnet: {e}")
    return app.run()
