
import os
import sys
import numpy as np

# Add csec_datagen to path
sys.path.append('/media/john/6217595f-2db8-47e4-9c64-0105d851d46c/models')

try:
    from csec_datagen import APT_PROFILES, KP14AugmentedGenerator, TrafficGenerator
except ImportError as e:
    print(f"Failed to import csec_datagen: {e}")
    sys.exit(1)

def generate_threat_db(samples_per_class=2000, output_file='threat_tensors.bin'):
    print(f"--- Generating ASIC Threat Tensor DB ---")
    print(f"Samples per class: {samples_per_class}")
    
    all_features = []
    labels = []
    
    # We'll map each APT class to an ID
    class_map = list(APT_PROFILES.keys())
    
    for class_id, apt_class in enumerate(class_map):
        print(f"Generating for {apt_class}...")
        profile = APT_PROFILES[apt_class]
        
        # Create augmented generator (Network + KP14 Binary features)
        base_gen = TrafficGenerator(profile)
        aug_gen = KP14AugmentedGenerator(base_gen, apt_class=apt_class)
        
        for _ in range(samples_per_class):
            sample = aug_gen.generate_sample(duration_sec=60.0)
            features = sample['features'] # 160-dim vector
            all_features.append(features.astype(np.float32))
            labels.append(class_id)
            
    # Convert to numpy array
    db_array = np.array(all_features)
    print(f"Generated DB Shape: {db_array.shape}") # Expected: (num_classes * samples, 160)
    
    # Save as flat binary for the ASIC (C code) to load
    db_array.tofile(output_file)
    print(f"Success! Saved to {output_file}")
    
    # Save mapping for the orchestrator to report the correct class name
    with open('apt_class_map.txt', 'w') as f:
        for i, name in enumerate(class_map):
            f.write(f"{i}:{name}\n")

if __name__ == "__main__":
    generate_threat_db()
