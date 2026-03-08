
import os
import sys
import time
import numpy as np
import hashlib
import re
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# ASIC Shared Memory Path
ASIC_FEED = "/tmp/asic_code_feed"

class SemanticCodeEncoder:
    """Real-world Locality Sensitive Hashing (SimHash) for Code"""
    def __init__(self, dims=160):
        self.dims = dims

    def encode(self, text):
        # 1. Clean and tokenize code (remove comments/whitespace)
        text = re.sub(r'#.*|//.*|/\*[\s\S]*?\*/', '', text)
        tokens = re.findall(r'\w+', text.lower())
        
        if not tokens:
            return np.zeros(self.dims, dtype=np.float32)

        # 2. Project tokens into bit-space
        v = np.zeros(self.dims)
        for token in tokens:
            # Deterministic hash of the token
            h = hashlib.sha256(token.encode()).digest()
            # Convert bytes to bit array
            bits = np.unpackbits(np.frombuffer(h, dtype=np.uint8))
            
            for i in range(min(len(bits), self.dims)):
                if bits[i]:
                    v[i] += 1
                else:
                    v[i] -= 1
        
        # 3. Create the SimHash vector
        # Normalizing to range [0, 1] for the QIHSE engine
        fingerprint = (v > 0).astype(np.float32)
        return fingerprint

class CodeIndexer(FileSystemEventHandler):
    def __init__(self, project_path):
        self.project_path = project_path
        self.encoder = SemanticCodeEncoder(dims=160)
        print(f"[ASIC-WINDSURF] Real Semantic Core Active. Monitoring: {project_path}")

    def on_modified(self, event):
        if event.is_directory or not event.src_path.endswith(('.py', '.c', '.h', '.js', '.ts')):
            return
        self.process_file(event.src_path)

    def process_file(self, file_path):
        try:
            with open(file_path, 'r') as f:
                content = f.read()
            
            # REAL FEATURE EXTRACTION (Deterministic LSH)
            vector = self.encoder.encode(content)
            
            # Metadata for the packet: [PID(4) | UID(4) | TYPE(4) | VECTOR(160*4)]
            # We'll use a simplified binary format for the ASIC pipe
            with open(ASIC_FEED, "ab") as f:
                f.write(vector.tobytes())
            
            print(f"[ASIC-OFFLOAD] Indexed real semantic vector for: {os.path.basename(file_path)}")
                
        except Exception as e:
            print(f"Error indexing {file_path}: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(1)
        
    path = sys.argv[1]
    event_handler = CodeIndexer(path)
    observer = Observer()
    observer.schedule(event_handler, path, recursive=True)
    observer.start()
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
