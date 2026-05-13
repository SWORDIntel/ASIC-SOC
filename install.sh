#!/bin/bash
# EDR dependency installer
# Optimized for Debian/Ubuntu

set -e

echo "--- EDR INSTALLER: PROVISIONING SYSTEM ---"

# 1. Update package lists
sudo apt-get update

# 2. Install Build Essentials & Hardware Headers
echo "[*] Installing Toolchain & Hardware Headers..."
sudo apt-get install -y build-essential clang llvm libelf-dev bc dwarves

# 3. Install EDR runtime dependencies
echo "[*] Installing EDR runtime libraries (libbpf, logrotate)..."
sudo apt-get install -y libbpf-dev libelf-dev logrotate

# 4. Compile backend
echo "[*] Compiling ASIC Backend..."
cd dev && make clean && make -j"$(nproc)" && cd ..

# 5. Install runtime files
echo "[*] Installing runtime files..."
sudo install -d -m 0755 -o root -g root /usr/local/bin /usr/local/lib/asic-edr /etc/asic-edr /etc/logrotate.d
sudo install -d -m 0750 -o root -g root /var/log/asic-edr
sudo install -m 0755 -o root -g root dev/asic_main /usr/local/bin/asic-edr
sudo install -m 0644 -o root -g root dev/asic_sensor.bpf.o /usr/local/lib/asic-edr/asic_sensor.bpf.o
sudo install -m 0644 -o root -g root config/rules.conf /etc/asic-edr/rules.conf
sudo install -m 0644 -o root -g root packaging/logrotate/asic-edr /etc/logrotate.d/asic-edr
sudo install -m 0644 -o root -g root asic-soc.service /etc/systemd/system/asic-edr.service
if command -v systemctl >/dev/null 2>&1; then
    sudo systemctl daemon-reload
fi

echo "--- INSTALLATION COMPLETE: EDR AGENT READY ---"
echo "Run with: sudo /usr/local/bin/asic-edr --bpf /usr/local/lib/asic-edr/asic_sensor.bpf.o -o /var/log/asic-edr/events.jsonl"
echo "Systemd unit installed as: asic-edr.service"
