import ipaddress
import os
import unittest

from natshare.dhcp import Dnsmasq
from natshare.wifi import Hostapd


class ConfigTest(unittest.TestCase):
    def test_short_passphrase_rejected(self):
        with self.assertRaises(ValueError):
            Hostapd("wlan0", password="short")

    def test_dnsmasq_config_and_cleanup(self):
        d = Dnsmasq("eth2", ipaddress.ip_network("10.42.0.0/24"))
        self.assertEqual(str(d.gateway), "10.42.0.1")
        self.assertEqual((str(d.range[0]), str(d.range[1])), ("10.42.0.10", "10.42.0.100"))
        d.stop()
        self.assertFalse(os.path.exists(d.conf))
