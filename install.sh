#!/bin/bash
# QIHSE SECURITY ASIC - Dependency Installer
# Optimized for Debian/Ubuntu (Trixie/Sid)

set -e

echo "--- QIHSE ASIC INSTALLER: PROVISIONING SYSTEM ---"

# 1. Update package lists
sudo apt-get update

# 2. Install Build Essentials & Hardware Headers
echo "[*] Installing Toolchain & Hardware Headers..."
sudo apt-get install -y build-essential clang-18 llvm-18 libelf-dev bc dwarves

# 3. Install ASIC Core Dependencies
echo "[*] Installing ASIC Runtime Libraries (libpci, libbpf, OpenCL)..."
sudo apt-get install -y libpci-dev libbpf-dev ocl-icd-opencl-dev opencl-headers

# 4. Install Sensor Dependencies
echo "[*] Installing RF & Hardware Sensor Utilities..."
sudo apt-get install -y iw wireless-tools pciutils

# 5. Install Python Runtime Dependencies
echo "[*] Installing Dashboard Telemetry Stack..."
sudo apt-get install -y python3 python3-pip python3-psutil python3-rich python3-numpy python3-watchdog

# 6. Verify PCI Access
echo "[*] Verifying Intel ME PCI Presence..."
if lspci | grep -q "Management Engine"; then
    echo "    [OK] Intel ME Interface detected."
else
    echo "    [WARN] Intel ME PCI device not found. L3+ Hammering will be disabled."
fi

# 7. Compile Backend
echo "[*] Compiling ASIC Backend..."
cd dev && make clean && make && cd ..

echo "--- INSTALLATION COMPLETE: ASI COMMAND CENTER READY ---"
echo "Run with: sudo python3 scripts/asic_dashboard.py <net_iface> <wifi_iface>"
