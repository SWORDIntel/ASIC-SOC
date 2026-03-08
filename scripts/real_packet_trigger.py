
from scapy.all import IP, TCP, send, Raw
import time

def send_threat_packets(interface="lo", count=50):
    print(f"--- Launching REAL Network Threat Burst on {interface} ---")
    
    # 1. Signature: curl -sL
    # 2. Signature: python -c
    sigs = [b"curl -sL", b"python -c"]
    
    for i in range(count):
        for sig in sigs:
            # Craft a TCP packet with the signature in the payload
            pkt = IP(dst="192.168.1.118")/TCP(dport=80)/Raw(load=sig + b" malicious_payload_" + str(i).encode())
            send(pkt, iface=interface, verbose=False)
            time.sleep(0.05)
            
    print("--- Burst Complete ---")

if __name__ == "__main__":
    # We send on loopback so the XDP sensor picks it up if attached to lo, 
    # but the ASIC is attached to enp4s0/wlp2s0. 
    # I will send to the IP address of enp4s0 instead.
    send_threat_packets(interface="lo", count=50)
