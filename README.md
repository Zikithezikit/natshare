# natshare

Transient, userspace Internet Connection Sharing for Linux. Share one interface's
connection (`--wan`) with clients on another (`--lan`, Ethernet or Wi-Fi) without
touching `ip_forward`, `iptables`/`nftables` or kernel routes. Everything is torn
down on `Ctrl-C` / `SIGTERM`.

## How it works

```
 clients ──L2──> [LAN iface] ──AF_PACKET──> natshare (Python NAT) ──sockets──> [WAN iface]
                     ▲
              dnsmasq (DHCP + DNS), hostapd (Wi-Fi AP, if LAN is wireless)
```

- The LAN interface temporarily gets the gateway address (first host of the
  subnet), so the kernel answers ARP and `dnsmasq` serves DHCP/DNS on it.
- Client IPv4 frames are read from an `AF_PACKET` socket. TCP, UDP and ICMP echo
  flows are terminated in userspace and re-originated from ordinary sockets bound
  to the WAN interface (`SO_BINDTODEVICE`); replies are rebuilt into packets and
  sent back to the client.
- `natshare/tun.py` provides a `/dev/net/tun` wrapper. It is not on the default
  path: the kernel will not deliver packets from one interface to a TUN device
  without forwarding enabled, which this tool deliberately avoids.

## Requirements

- Linux, Python 3.9+, run as root (`CAP_NET_ADMIN` and `CAP_NET_RAW`)
- `ip` (iproute2), `dnsmasq`
- `hostapd` and `rfkill` when the LAN interface is wireless

## Install

```sh
make install        # system-wide (sudo; add PIP_FLAGS=--break-system-packages if pip refuses)
make install-dev    # .venv with editable install + dev tools
```

## Usage

```sh
sudo natshare --wan eth1 --lan eth2
sudo natshare -w eth1 -l wlan0 -s MyNet -p 'correct horse'   # Wi-Fi AP
```

| Option | Meaning |
| --- | --- |
| `--wan, -w` | Interface with Internet access |
| `--lan, -l` | Interface to share to |
| `--ssid, -s` | AP name when LAN is wireless (default `natshare-ap`) |
| `--password, -p` | WPA2 passphrase, 8-63 chars (open network if omitted) |
| `--subnet` | Client subnet, `/27` or larger (default `10.42.0.0/24`) |
| `--verbose, -v` | Debug logging |

Temporary files live in `/tmp/natshare_*` and are removed on exit. If the Wi-Fi
interface is managed by NetworkManager, stop it managing the interface first.

## Limitations

- Pure-Python forwarding is slower than kernel NAT.
- IPv4 only; IP fragments are dropped; TCP uses a fixed 64 KB window without
  window scaling or SACK. Wi-Fi uses channel 6 (2.4 GHz).
- Client-to-client traffic is not relayed.
- DNS is answered by `dnsmasq` using the host's own resolvers, which are not
  necessarily reached via `--wan`.

## Development

```sh
make check    # lint (ruff) + typecheck (mypy) + tests (pytest)
make build    # sdist + wheel in dist/
make help
```

MIT licensed.
