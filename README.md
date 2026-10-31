# natshare

Share your computer's internet connection with other devices, then leave no trace.

Plug a laptop into one network port, or turn your Wi-Fi card into a hotspot, and
natshare passes the internet through from another connection. Nothing on your
system is permanently changed, and when you press `Ctrl-C` everything is put back
the way it was.

To the network on the other side, it just looks like one computer. Your other
devices don't show up.

## Quick start

You need Linux, Python 3.9+, root access, and these installed: `dnsmasq`
(plus `hostapd` if you want a Wi-Fi hotspot).

```sh
git clone https://github.com/Zikithezikit/natshare.git
cd natshare
make install
```

Share the internet from `eth1` out through `eth2`:

```sh
sudo natshare --wan eth1 --lan eth2
```

Or make a Wi-Fi hotspot on `wlan0`:

```sh
sudo natshare --wan eth1 --lan wlan0 --ssid MyNetwork --password 'something secret'
```

Not sure of your interface names? Run `ip link` to list them.

Press `Ctrl-C` when you're done.

## Options

| Option | What it does |
| --- | --- |
| `--wan`, `-w` | The connection that has internet |
| `--lan`, `-l` | Where to share it (a cable port or Wi-Fi card) |
| `--ssid`, `-s` | Hotspot name (default `natshare-ap`) |
| `--password`, `-p` | Hotspot password, 8 characters or more (open if left out) |
| `--subnet` | Address range for your devices (default `10.42.0.0/24`) |
| `--verbose`, `-v` | Show more detail while it runs |

## Good to know

- It's slower than your system's built-in sharing, since it's all done in Python.
  Fine for browsing and streaming, not for maxing out a fast line.
- IPv4 only.
- If a Wi-Fi hotspot won't start, your network manager may be holding the card.
  Tell it to leave that card alone first.
- Details like the browser you use can still be visible to websites. natshare
  hides your devices, not what they say about themselves.

## For developers

```sh
make install-dev   # set up a local environment
make check         # lint, type check and tests
make build         # build a package
make help          # list everything
```

MIT licensed.
