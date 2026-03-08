
import os
import numpy as np

def generate_vault7_marble_vectors(count=2000, dims=160):
    print(f"--- Generating Vault 7 (Marble) Threat Tensors ---")
    
    vectors = []
    for i in range(count):
        # Base noise
        vec = np.random.normal(0.1, 0.05, dims).astype(np.float32)
        
        # Marble specific features:
        # 1. XOR Obfuscation Profile (High entropy across certain indices)
        xor_indices = [10, 20, 30, 40, 50, 60, 70, 80]
        vec[xor_indices] += 0.8
        
        # 2. Language Bait (Chinese/Russian strings encoded as vector peaks)
        # Marble adds foreign language strings to throw off attribution
        bait_indices = [100, 101, 102, 105, 106, 107]
        vec[bait_indices] += 0.9
        
        # 3. Visual Studio 2013 Artifacts (specific padding/offsets)
        vec[140:150] += 0.6
        
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
        # Reshape to (N, 160)
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
        f.write("8:vault7_marble\n")
    print(f"Updated {db_file} and {map_file}")

if __name__ == "__main__":
    v7_vectors = generate_vault7_marble_vectors()
    append_to_db(v7_vectors)
