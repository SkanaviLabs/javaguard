#!/bin/sh
# javaguard network test peer: isolated interface, services bound to the tunnel address only.
set -e
CLIENT_PUB="$1"
[ -n "$CLIENT_PUB" ] || { echo "usage: setup-server.sh <client public key>" >&2; exit 2; }
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq --no-install-recommends wireguard-tools socat dnsmasq-base >/dev/null
mkdir -p /etc/jgtest /srv/jgtest
cd /etc/jgtest
[ -f server.key ] || (umask 077; wg genkey > server.key)
ip link del jgtest0 2>/dev/null || true
ip link add jgtest0 type wireguard
wg set jgtest0 listen-port 51871 private-key /etc/jgtest/server.key peer $CLIENT_PUB allowed-ips 10.77.0.1/32,fd77::1/128
ip addr add 10.77.0.2/24 dev jgtest0
ip -6 addr add fd77::2/64 dev jgtest0
ip link set jgtest0 up
# Test content
[ -f /srv/jgtest/1m.bin ] || head -c 1048576 /dev/urandom > /srv/jgtest/1m.bin
[ -f /srv/jgtest/5m.bin ] || head -c 5242880 /dev/urandom > /srv/jgtest/5m.bin
[ -f /srv/jgtest/50m.bin ] || head -c 52428800 /dev/urandom > /srv/jgtest/50m.bin
echo 'hello from the network test peer' > /srv/jgtest/index.html
(cd /srv/jgtest && sha256sum *.bin > SHA256SUMS)
# Services as transient units, bound to the tunnel address only
for u in jgtest-http jgtest-http6 jgtest-sink jgtest-sink6 jgtest-echo jgtest-echo6 jgtest-dns; do systemctl stop $u 2>/dev/null || true; systemctl reset-failed $u 2>/dev/null || true; done
systemd-run --quiet --unit=jgtest-http --working-directory=/srv/jgtest /usr/bin/python3 -m http.server 8080 --bind 10.77.0.2
systemd-run --quiet --unit=jgtest-http6 --working-directory=/srv/jgtest /usr/bin/python3 -m http.server 8080 --bind fd77::2
systemd-run --quiet --unit=jgtest-sink /usr/bin/socat TCP-LISTEN:9001,bind=10.77.0.2,fork,reuseaddr EXEC:/usr/bin/sha256sum
systemd-run --quiet --unit=jgtest-sink6 /usr/bin/socat TCP6-LISTEN:9001,bind=[fd77::2],fork,reuseaddr EXEC:/usr/bin/sha256sum
systemd-run --quiet --unit=jgtest-echo /usr/bin/socat UDP-LISTEN:7000,bind=10.77.0.2,fork,reuseaddr EXEC:/bin/cat
systemd-run --quiet --unit=jgtest-echo6 /usr/bin/socat UDP6-LISTEN:7000,bind=[fd77::2],fork,reuseaddr EXEC:/bin/cat
systemd-run --quiet --unit=jgtest-dns /usr/sbin/dnsmasq --keep-in-foreground --conf-file=/dev/null --no-resolv --no-hosts --user=root --listen-address=10.77.0.2 --bind-interfaces --host-record=web.jgtest,10.77.0.2,fd77::2 --cname=alias.jgtest,web.jgtest
# Firewall: the WireGuard port, and traffic arriving over the tunnel interface
ufw allow 51871/udp comment 'javaguard network tests' >/dev/null
ufw allow in on jgtest0 comment 'javaguard network tests' >/dev/null
echo "SERVER_PUB $(wg pubkey < /etc/jgtest/server.key)"
systemctl is-active jgtest-http jgtest-http6 jgtest-sink jgtest-sink6 jgtest-echo jgtest-echo6 jgtest-dns | tr '\n' ' '; echo
