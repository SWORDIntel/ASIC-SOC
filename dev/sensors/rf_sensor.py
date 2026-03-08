
import subprocess
import time
import sys

def get_5ghz_signals(interface="wlp2s0"):
    try:
        # Run an active scan to capture signal strengths (requires sudo, but we'll run orchestrator as root)
        cmd = ["iw", "dev", interface, "scan"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=2)
        
        signals = []
        in_5ghz = False
        
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith("freq:"):
                freq = int(line.split()[1])
                # Check if it's in the C-Band (5 GHz)
                in_5ghz = (5000 <= freq <= 5900)
            elif in_5ghz and line.startswith("signal:"):
                # Extract the dBm value (e.g., "-57.00 dBm")
                dbm = float(line.split()[1])
                signals.append(dbm)
                
        return signals
    except Exception:
        return []

if __name__ == "__main__":
    if len(sys.argv) < 2:
        interface = "wlp2s0"
    else:
        interface = sys.argv[1]
        
    print(f"[RF SENSOR] L4 C-Band Monitoring Active on {interface}")
    while True:
        signals = get_5ghz_signals(interface)
        if signals:
            # We pad/truncate to 10 signals for the GPU vector
            vec = signals[:10] + [-100.0] * (10 - len(signals))
            # Output format for the orchestrator pipe
            print("RF_DATA:" + ",".join(f"{x:.1f}" for x in vec), flush=True)
        time.sleep(1.0) # Scan every 1 second
