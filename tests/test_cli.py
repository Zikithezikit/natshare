import unittest
from unittest import mock

from natshare import cli
from natshare.core import Config, NatShare


class CliTest(unittest.TestCase):
    def test_requires_wan_and_lan(self):
        with self.assertRaises(SystemExit), mock.patch("sys.stderr"):
            cli.main([])

    def test_non_root_fails_fast(self):
        with mock.patch("os.geteuid", return_value=1000), mock.patch("sys.stderr"):
            self.assertEqual(cli.main(["-w", "eth1", "-l", "eth2"]), 1)

    def test_bad_subnet_rejected(self):
        with mock.patch("os.geteuid", return_value=0):
            self.assertIn("subnet", NatShare(Config("lo", "lo", subnet="10.0.0.0/30"))._check())

    def test_same_interface_rejected(self):
        with mock.patch("os.geteuid", return_value=0):
            self.assertIn("different", NatShare(Config("lo", "lo"))._check())
