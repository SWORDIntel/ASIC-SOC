import os
import re

def ultimate_fix():
    # 1. nvidia-drm-drv.c
    path = 'NVIDIA-Linux-x86_64-390.157/kernel/nvidia-drm/nvidia-drm-drv.c'
    if os.path.exists(path):
        with open(path, 'r') as f: content = f.read()
        if 'linux/version.h' not in content: content = '#include <linux/version.h>\n' + content
        content = content.replace('DRM_UNLOCKED', '0')
        if 'drm_client.h' not in content:
            content = content.replace('#include <drm/drm_drv.h>', '#include <drm/drm_drv.h>\n#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)\n#include <drm/drm_client.h>\n#endif')
        if '.fop_flags' not in content:
            fop_fix = """#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
    .fop_flags      = FOP_UNSIGNED_OFFSET,
#endif
};"""
            content = re.sub(r'(\s+)\.llseek\s+=\s+noop_llseek,?\n\};', r'\1.llseek         = noop_llseek,\n' + fop_fix, content)
        content = re.sub(r'(dev->mode_config\.fb_base = 0;)', r'#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 12, 0)\n    \1\n#endif', content)
        with open(path, 'w') as f: f.write(content)

    # 2. nvidia-drm-fb.c
    path = 'NVIDIA-Linux-x86_64-390.157/kernel/nvidia-drm/nvidia-drm-fb.c'
    if os.path.exists(path):
        with open(path, 'r') as f: content = f.read()
        if 'static void drm_helper_mode_fill_fb_struct' not in content:
            fb_fill_compat = """
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 11, 0)
static void drm_helper_mode_fill_fb_struct(struct drm_device *dev,
                                           struct drm_framebuffer *fb,
                                           const struct drm_mode_fb_cmd2 *mode_cmd)
{
    int i;
    fb->dev = dev;
    fb->format = drm_get_format_info(dev, mode_cmd);
    fb->width = mode_cmd->width;
    fb->height = mode_cmd->height;
    for (i = 0; i < 4; i++) {
        fb->pitches[i] = mode_cmd->pitches[i];
        fb->offsets[i] = mode_cmd->offsets[i];
    }
    fb->modifier = mode_cmd->modifier[0];
    fb->flags = mode_cmd->flags;
}
#endif
"""
            lines = content.splitlines()
            last_inc = 0
            for i, l in enumerate(lines):
                if l.startswith('#include'): last_inc = i
            lines.insert(last_inc + 1, fb_fill_compat)
            with open(path, 'w') as f: f.write("\n".join(lines))

    # 3. nv-linux.h
    path = 'NVIDIA-Linux-x86_64-390.157/kernel/common/inc/nv-linux.h'
    if os.path.exists(path):
        with open(path, 'r') as f: content = f.read()
        if 'linux/stdarg.h' not in content:
            content = content.replace('#include <linux/kernel.h>', '#include <linux/kernel.h>\n#include <linux/stdarg.h>\n#include <linux/device.h>\n#include <linux/swiotlb.h>')
        with open(path, 'w') as f: f.write(content)

    # 4. nv-mm.h (COMPLETE REWRITE OF WRAPPERS)
    path = 'NVIDIA-Linux-x86_64-390.157/kernel/common/inc/nv-mm.h'
    if os.path.exists(path):
        with open(path, 'r') as f: content = f.read()
        # Kill the old complex mess and replace with clean 6.12-compatible wrappers
        clean_mm = """
#ifndef __NV_MM_H__
#define __NV_MM_H__

#include <linux/version.h>
#include <linux/mm.h>
#include <linux/sched.h>

static inline long NV_GET_USER_PAGES(unsigned long start, unsigned long nr_pages, int write, int force, struct page **pages, struct vm_area_struct **vmas) {
    unsigned int flags = 0;
    if (write) flags |= FOLL_WRITE;
    if (force) flags |= FOLL_FORCE;
    return get_user_pages(start, nr_pages, flags, pages);
}

static inline long NV_GET_USER_PAGES_REMOTE(struct task_struct *tsk, struct mm_struct *mm, unsigned long start, unsigned long nr_pages, int write, int force, struct page **pages, struct vm_area_struct **vmas) {
    unsigned int flags = 0;
    if (write) flags |= FOLL_WRITE;
    if (force) flags |= FOLL_FORCE;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
    return get_user_pages_remote(mm, start, nr_pages, flags, pages, NULL);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 9, 0)
    return get_user_pages_remote(mm, start, nr_pages, flags, pages, vmas, NULL);
#else
    return get_user_pages_remote(tsk, mm, start, nr_pages, flags, pages, vmas);
#endif
}

static inline void nv_mmap_read_lock(struct mm_struct *mm) { mmap_read_lock(mm); }
static inline void nv_mmap_read_unlock(struct mm_struct *mm) { mmap_read_unlock(mm); }
static inline void nv_mmap_write_lock(struct mm_struct *mm) { mmap_write_lock(mm); }
static inline void nv_mmap_write_unlock(struct mm_struct *mm) { mmap_write_unlock(mm); }

static inline int nv_mm_rwsem_is_locked(struct mm_struct *mm) {
    return rwsem_is_locked(&mm->mmap_lock);
}

static inline unsigned long nv_page_fault_va(struct vm_fault *vmf) {
    return vmf->address;
}

#endif
"""
        with open(path, 'w') as f: f.write(clean_mm)

    # 5. nv-acpi.c
    path = 'NVIDIA-Linux-x86_64-390.157/kernel/nvidia/nv-acpi.c'
    if os.path.exists(path):
        with open(path, 'r') as f: content = f.read()
        content = content.replace('#if !defined(NV_ACPI_DEVICE_OPS_REMOVE_ARGUMENT_COUNT) || (NV_ACPI_DEVICE_OPS_REMOVE_ARGUMENT_COUNT == 2)', 
                                  '#if (!defined(NV_ACPI_DEVICE_OPS_REMOVE_ARGUMENT_COUNT) || (NV_ACPI_DEVICE_OPS_REMOVE_ARGUMENT_COUNT == 2)) && LINUX_VERSION_CODE < KERNEL_VERSION(6, 11, 0)')
        if 'static void nv_acpi_remove_one_arg' not in content:
             content = content.replace('static int         nv_acpi_remove_one_arg(struct acpi_device *device);', 
                                       '#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 11, 0)\nstatic void        nv_acpi_remove_one_arg(struct acpi_device *device);\n#else\nstatic int         nv_acpi_remove_one_arg(struct acpi_device *device);\n#endif')
             content = content.replace('static int nv_acpi_remove_one_arg(struct acpi_device *device)', 
                                       '#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 11, 0)\nstatic void nv_acpi_remove_one_arg(struct acpi_device *device)\n#else\nstatic int nv_acpi_remove_one_arg(struct acpi_device *device)\n#endif')
             content = content.replace('return status;', '#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 11, 0)\n    return;\n#else\n    return status;\n#endif')
        with open(path, 'w') as f: f.write(content)

    # 6. nv-memdbg.h
    path = 'NVIDIA-Linux-x86_64-390.157/kernel/common/inc/nv-memdbg.h'
    if os.path.exists(path):
        with open(path, 'r') as f: content = f.read()
        content = re.sub(r'#define NV_MEMDBG_ADD\(ptr, size\)\s*$', '#define NV_MEMDBG_ADD(ptr, size) do { } while (0)', content, flags=re.MULTILINE)
        content = re.sub(r'#define NV_MEMDBG_REMOVE\(ptr, size\)\s*$', '#define NV_MEMDBG_REMOVE(ptr, size) do { } while (0)', content, flags=re.MULTILINE)
        with open(path, 'w') as f: f.write(content)

    # 7. nvidia-modeset-linux.c
    path = 'NVIDIA-Linux-x86_64-390.157/kernel/nvidia-modeset/nvidia-modeset-linux.c'
    if os.path.exists(path):
        with open(path, 'r') as f: content = f.read()
        content = content.replace('static struct nv_kthread_q nvkms_kthread_q;', 'static nv_kthread_q_t nvkms_kthread_q;')
        with open(path, 'w') as f: f.write(content)

if __name__ == "__main__":
    ultimate_fix()
    print("Ultimate fix complete.")
