import os
import re

def patch_file(path, search_pattern, replacement, multi_line=False):
    if not os.path.exists(path):
        print(f"File not found: {path}")
        return
    with open(path, 'r') as f:
        content = f.read()
    
    if multi_line:
        new_content = re.sub(search_pattern, replacement, content, flags=re.DOTALL)
    else:
        new_content = re.sub(search_pattern, replacement, content)
    
    if new_content != content:
        with open(path, 'w') as f:
            f.write(new_content)
        print(f"Patched: {path}")
    else:
        print(f"No changes made to: {path}")

# 1. Patch nv-memdbg.h to fix "suggest braces around empty body"
memdbg_h = 'NVIDIA-Linux-x86_64-390.157/kernel/common/inc/nv-memdbg.h'
patch_file(memdbg_h, r'#define NV_MEMDBG_ADD\(ptr, size\)', '#define NV_MEMDBG_ADD(ptr, size) do { } while (0)')
patch_file(memdbg_h, r'#define NV_MEMDBG_REMOVE\(ptr, size\)', '#define NV_MEMDBG_REMOVE(ptr, size) do { } while (0)')

# 2. Patch nvidia-drm-drv.c
drm_drv_path = 'NVIDIA-Linux-x86_64-390.157/kernel/nvidia-drm/nvidia-drm-drv.c'
if os.path.exists(drm_drv_path):
    with open(drm_drv_path, 'r') as f:
        content = f.read()
    if 'linux/version.h' not in content:
        content = '#include <linux/version.h>\n' + content
    if 'DRM_UNLOCKED' not in content:
        content = content.replace('#include <drm/drm_drv.h>', 
                                '#include <drm/drm_drv.h>\n#ifndef DRM_UNLOCKED\n#define DRM_UNLOCKED 0\n#endif')
    
    content = re.sub(r'dev->mode_config\.fb_base = 0;', 
                     '#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 12, 0)\n    dev->mode_config.fb_base = 0;\n#endif', content)
    content = re.sub(r'nv_drm_driver\.dumb_destroy     = nv_drm_dumb_destroy;', 
                     '#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 12, 0)\n    nv_drm_driver.dumb_destroy     = nv_drm_dumb_destroy;\n#endif', content)
    with open(drm_drv_path, 'w') as f:
        f.write(content)
    print(f"Patched: {drm_drv_path}")

# 3. Patch nvidia-modeset-linux.c
modeset_path = 'NVIDIA-Linux-x86_64-390.157/kernel/nvidia-modeset/nvidia-modeset-linux.c'
patch_file(modeset_path, r'static struct nv_kthread_q nvkms_kthread_q;', 'static nv_kthread_q_t nvkms_kthread_q;')
patch_file(modeset_path, r'struct nv_kthread_q \*', 'nv_kthread_q_t *')

# 4. Patch uvm8.c for vm_flags and other issues
uvm8_path = 'NVIDIA-Linux-x86_64-390.157/kernel/nvidia-uvm/uvm8.c'
patch_file(uvm8_path, r'vma->vm_flags \|= VM_MIXEDMAP \| VM_DONTEXPAND;', 
           '#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)\n    vm_flags_set(vma, VM_MIXEDMAP | VM_DONTEXPAND);\n#else\n    vma->vm_flags |= VM_MIXEDMAP | VM_DONTEXPAND;\n#endif')

# 5. Patch nv-linux.h to include nv-mm.h and version.h
nv_linux_h = 'NVIDIA-Linux-x86_64-390.157/kernel/common/inc/nv-linux.h'
with open(nv_linux_h, 'r') as f:
    content = f.read()
if 'nv-mm.h' not in content:
    content = content.replace('#include <linux/mm.h>', '#include <linux/mm.h>\n#include <linux/version.h>\n#include "nv-mm.h"')
with open(nv_linux_h, 'w') as f:
    f.write(content)
print(f"Patched: {nv_linux_h}")

print("Comprehensive patching complete.")
