#!/usr/bin/env bash
set -euo pipefail

echo "[*] Installing dependencies..."
sudo apt update
sudo apt install -y build-essential python3-dev python3-pip cython uvloop \
    curl jq siege wrk nginx

echo "[*] Raising ulimit for open files..."
if ! grep -q "ulimit -n" ~/.bashrc; then
    echo "ulimit -n 1048576" >> ~/.bashrc
fi

echo "[*] Applying sysctl tuning..."
sudo tee /etc/sysctl.d/99-proxy-bench.conf <<EOF
# Max TCP backlog
net.core.somaxconn=65535
# Max open files per process
fs.file-max=2097152
# Port range
net.ipv4.ip_local_port_range=1024 65535
# Faster socket recycling
net.ipv4.tcp_fin_timeout=15
net.ipv4.tcp_tw_reuse=1
# Buffers
net.core.rmem_max=268435456
net.core.wmem_max=268435456
EOF

sudo sysctl --system

echo "[*] Tuning complete. Re-login or run 'ulimit -n 1048576' now."
