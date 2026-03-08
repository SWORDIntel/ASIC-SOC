
import os
import sys
import time
import hashlib
import re
import struct
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# ASIC Shared Memory Path (Named Pipe)
ASIC_FEED = "/tmp/asic_code_feed"

class CodeIndexer(FileSystemEventHandler):
    def __init__(self, project_path):
        self.project_path = project_path
        print(f"[ASIC-WINDSURF] Code Feeder Active. Offloading to Monolith ASIC.")

    def on_modified(self, event):
        if event.is_directory or not event.src_path.endswith(('.py', '.c', '.h', '.js', '.ts')):
            return
        self.process_file(event.src_path)

    def process_file(self, file_path):
        try:
            with open(file_path, 'r') as f:
                content = f.read()
            
            # Clean and tokenize
            text = re.sub(r'#.*|//.*|/\*[\s\S]*?\*/', '', content)
            tokens = re.findall(r'\w+', text.lower())
            
            if not tokens:
                return

            # Deterministic Token Hashing (Fast)
            # We send raw uint32 hashes to the ASIC context core
            token_hashes = []
            for token in tokens:
                h = int(hashlib.md5(token.encode()).hexdigest()[:8], 16)
                token_hashes.append(h)
            
            # Pack as binary uint32 array
            # MAX_PAYLOAD is 256 bytes = 64 tokens
            payload = struct.pack(f"{min(len(token_hashes), 64)}I", *token_hashes[:64])
            
            # Offload to ASIC via Named Pipe
            try:
                # Open non-blocking to avoid hanging if monolith is not reading
                fd = os.open(ASIC_FEED, os.O_WRONLY | os.O_NONBLOCK)
                os.write(fd, payload)
                os.close(fd)
                print(f"[ASIC-OFFLOAD] Dispatched {len(token_hashes)} tokens for: {os.path.basename(file_path)}")
            except OSError:
                # Pipe not ready or full
                pass
                
        except Exception as e:
            print(f"Error feeding {file_path}: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        path = "."
    else:
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
