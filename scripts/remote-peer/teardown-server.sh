#!/bin/sh
# Removes everything setup-server.sh created (packages are left installed).
for u in jgtest-http jgtest-http6 jgtest-sink jgtest-sink6 jgtest-echo jgtest-echo6 jgtest-dns; do systemctl stop $u 2>/dev/null; systemctl reset-failed $u 2>/dev/null; done
ip link del jgtest0 2>/dev/null
ufw delete allow 51871/udp >/dev/null 2>&1
ufw delete allow in on jgtest0 >/dev/null 2>&1
rm -rf /etc/jgtest /srv/jgtest
echo teardown done
