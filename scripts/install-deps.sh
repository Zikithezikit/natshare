#!/bin/sh
# Install the system programs natshare needs: ip, dnsmasq, hostapd, rfkill.
# Detects the package manager; skips anything already present. Needs root (uses sudo if not).
set -eu

missing=""
for bin in ip dnsmasq hostapd rfkill; do
    command -v "$bin" >/dev/null 2>&1 || missing="$missing $bin"
done
if [ -z "$missing" ]; then
    echo "natshare: system dependencies already installed"
    exit 0
fi
echo "natshare: installing missing system dependencies:$missing"

SUDO=""
[ "$(id -u)" -eq 0 ] || SUDO="sudo"

if command -v apt-get >/dev/null 2>&1; then
    # dnsmasq-base ships the binary without a system service competing for port 53
    $SUDO apt-get update
    $SUDO apt-get install -y iproute2 dnsmasq-base hostapd rfkill
elif command -v dnf >/dev/null 2>&1; then
    $SUDO dnf install -y iproute dnsmasq hostapd util-linux
elif command -v yum >/dev/null 2>&1; then
    $SUDO yum install -y iproute dnsmasq hostapd util-linux
elif command -v pacman >/dev/null 2>&1; then
    $SUDO pacman -S --needed --noconfirm iproute2 dnsmasq hostapd util-linux
elif command -v zypper >/dev/null 2>&1; then
    $SUDO zypper --non-interactive install iproute2 dnsmasq hostapd util-linux
elif command -v apk >/dev/null 2>&1; then
    $SUDO apk add iproute2 dnsmasq hostapd util-linux
else
    echo "natshare: unknown package manager; please install manually:$missing" >&2
    exit 1
fi

# A system-wide dnsmasq/hostapd service would fight natshare for port 53 / the Wi-Fi card.
if command -v systemctl >/dev/null 2>&1; then
    for svc in dnsmasq hostapd; do
        $SUDO systemctl disable --now "$svc" >/dev/null 2>&1 || true
    done
fi
echo "natshare: system dependencies installed"
