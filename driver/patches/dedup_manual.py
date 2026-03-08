import os

path = 'NVIDIA-Linux-x86_64-390.157/kernel/nvidia-drm/nvidia-drm-drv.c'
if os.path.exists(path):
    with open(path, 'r') as f:
        lines = f.readlines()
    
    new_lines = []
    in_block = False
    block_count = 0
    
    # We want to remove the SECOND occurrence of the block starting with #if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
    # AND ending with #endif, but only if it contains "Register a DRM client"
    
    i = 0
    while i < len(lines):
        if "#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)" in lines[i]:
            # Peek ahead to see if it's the client reg block
            is_client_block = False
            if i+1 < len(lines) and "/* Register a DRM client" in lines[i+1]:
                is_client_block = True
            
            if is_client_block:
                block_count += 1
                if block_count > 1:
                    # Skip this block
                    while i < len(lines) and "#endif" not in lines[i]:
                        i += 1
                    i += 1 # skip #endif
                    continue
        
        new_lines.append(lines[i])
        i += 1

    with open(path, 'w') as f:
        f.writelines(new_lines)
    print("Manual deduplication complete.")
