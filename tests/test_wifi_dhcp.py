import ipaddress
import os
import unittest
from unittest import mock

from natshare.dhcp import Dnsmasq
from natshare.wifi import Hostapd


class ConfigTest(unittest.TestCase):
    def test_short_passphrase_rejected(self):
        with self.assertRaises(ValueError):
            Hostapd("wlan0", password="short")

    def test_dnsmasq_does_not_leak_local_names(self):
        d = Dnsmasq("eth2", ipaddress.ip_network("10.42.0.0/24"))
        with mock.patch("subprocess.Popen"):
            d.start()
        try:
            with open(d.conf) as f:
                lines = f.read().split()
            self.assertIn("domain-needed", lines)
            self.assertIn("bogus-priv", lines)
            self.assertIn("except-interface=lo", lines)
            self.assertFalse(any(line.startswith("add-mac") for line in lines))
        finally:
            d.stop()

    def test_dnsmasq_config_and_cleanup(self):
        d = Dnsmasq("eth2", ipaddress.ip_network("10.42.0.0/24"))
        self.assertEqual(str(d.gateway), "10.42.0.1")
        self.assertEqual((str(d.range[0]), str(d.range[1])), ("10.42.0.10", "10.42.0.100"))
        d.stop()
        self.assertFalse(os.path.exists(d.conf))
