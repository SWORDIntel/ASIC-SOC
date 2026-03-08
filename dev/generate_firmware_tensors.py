
import os
import numpy as np

def generate_firmware_implant_vectors(count=2000, dims=160):
    print(f"--- Generating Firmware Implant (UEFI/SMM) Threat Tensors ---")
    
    vectors = []
    for i in range(count):
        # Base noise
        vec = np.random.normal(0.1, 0.05, dims).astype(np.float32)
        
        # Firmware/UEFI specific features:
        # 1. SMI Trigger Patterns (I/O Port 0xB2, 0xCF8/0xCFC)
        # These are common for SMM escapes and UEFI variable manipulation
        smi_indices = [5, 15, 25, 35, 45]
        vec[smi_indices] += 0.85
        
        # 2. SPI Flash Controller Access (Direct hardware mapping signatures)
        # Seen in Lojax and MoonBounce implants
        spi_indices = [70, 71, 72, 75, 76]
        vec[spi_indices] += 0.9
        
        # 3. UEFI Shell/Runtime Service call patterns
        # Specific instruction sequences for UEFI persistent storage
        uefi_indices = [110, 111, 115, 120]
        vec[uefi_indices] += 0.7
        
        # 4. Persistence Hook Signatures (SMM transition sequences)
        vec[150:158] += 0.65
        
        # Normalize
        norm = np.linalg.norm(vec)
        if norm > 0:
            vec /= norm
            
        vectors.append(vec)
        
    return np.array(vectors)

def append_to_db(new_vectors, db_file='threat_tensors.bin', map_file='apt_class_map.txt'):
    # Load existing DB
    if os.path.exists(db_file):
        existing_db = np.fromfile(db_file, dtype=np.float32)
        existing_db = existing_db.reshape(-1, 160)
        print(f"Existing DB: {existing_db.shape}")
        
        # Concatenate
        combined_db = np.vstack([existing_db, new_vectors])
    else:
        combined_db = new_vectors
        
    print(f"New DB Shape: {combined_db.shape}")
    combined_db.tofile(db_file)
    
    # Update map
    with open(map_file, 'a') as f:
        f.write("9:firmware_implant\n")
    print(f"Updated {db_file} and {map_file}")

if __name__ == "__main__":
    fw_vectors = generate_firmware_implant_vectors()
    append_to_db(fw_vectors)
