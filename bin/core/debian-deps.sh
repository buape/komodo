#!/bin/bash
set -eu

## Core deps installer

apt-get update
apt-get install -y git curl ca-certificates iproute2
# Fail the build rather than ship a pre-eMudhra-remediation trust store.
dpkg --compare-versions "$(dpkg-query -W -f='${Version}' ca-certificates)" ge '20250419+deb13u1'
update-ca-certificates

rm -rf /var/lib/apt/lists/*

# Starship prompt
curl -sS https://starship.rs/install.sh | sh -s -- --yes --bin-dir /usr/local/bin
echo 'export STARSHIP_CONFIG=/starship.toml' >> /root/.bashrc
echo 'eval "$(starship init bash)"' >> /root/.bashrc

