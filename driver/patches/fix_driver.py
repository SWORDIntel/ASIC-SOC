import os
import re

def patch_driver():
    # 1. nvidia-drm-drv.c
    path = 'NVIDIA-Linux-x86_64-390.157/kernel/nvidia-drm/nvidia-drm-drv.c'
    if os.path.exists(path):
        with open(path, 'r') as f: content = f.read()
        if 'linux/version.h' not in content: content = '#include <linux/version.h>\n' + content
        # Just replace DRM_UNLOCKED with 0 everywhere in this file
        content = content.replace('DRM_UNLOCKED', '0')
        content = re.sub(r'(dev->mode_config\.fb_base = 0;)', r'#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 12, 0)\n    \1\n#endif', content)
        content = re.sub(r'(nv_drm_driver\.dumb_destroy     = nv_drm_dumb_destroy;)', r'#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 12, 0)\n    \1\n#endif', content)
        with open(path, 'w') as f: f.write(content)

    # 2. nvidia-drm-fb.c
    path = 'NVIDIA-Linux-x86_64-390.157/kernel/nvidia-drm/nvidia-drm-fb.c'
    if os.path.exists(path):
        with open(path, 'r') as f: content = f.read()
        # Remove previous attempt at top of file
        content = re.sub(r'\n#include <linux/version\.h>\n#if LINUX_VERSION_CODE >= KERNEL_VERSION\(6, 11, 0\).*?#endif\n', '', content, flags=re.DOTALL)
        
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
            # Insert after the last include
            lines = content.splitlines()
            last_include = 0
            for i, line in enumerate(lines):
                if line.startswith('#include'): last_include = i
            lines.insert(last_include + 1, fb_fill_compat)
            content = "\n".join(lines)
            with open(path, 'w') as f: f.write(content)

    # 3. nvidia-drm-connector.c
    path = 'NVIDIA-Linux-x86_64-390.157/kernel/nvidia-drm/nvidia-drm-connector.c'
    if os.path.exists(path):
        with open(path, 'r') as f: content = f.read()
        content = content.replace('if (connector->override_edid)', 'if (connector->edid_blob_ptr)')
        with open(path, 'w') as f: f.write(content)

    # 4. nv-memdbg.h
    path = 'NVIDIA-Linux-x86_64-390.157/kernel/common/inc/nv-memdbg.h'
    if os.path.exists(path):
        with open(path, 'r') as f: content = f.read()
        content = re.sub(r'#define NV_MEMDBG_ADD\(ptr, size\)\s*$', '#define NV_MEMDBG_ADD(ptr, size) do { } while (0)', content, flags=re.MULTILINE)
        content = re.sub(r'#define NV_MEMDBG_REMOVE\(ptr, size\)\s*$', '#define NV_MEMDBG_REMOVE(ptr, size) do { } while (0)', content, flags=re.MULTILINE)
        with open(path, 'w') as f: f.write(content)

    # 5. nvidia-modeset-linux.c
    path = 'NVIDIA-Linux-x86_64-390.157/kernel/nvidia-modeset/nvidia-modeset-linux.c'
    if os.path.exists(path):
        with open(path, 'r') as f: content = f.read()
        content = content.replace('static struct nv_kthread_q nvkms_kthread_q;', 'static nv_kthread_q_t nvkms_kthread_q;')
        content = content.replace('struct nv_kthread_q *', 'nv_kthread_q_t *')
        content = content.replace('struct nv_kthread_q', 'nv_kthread_q_t')
        with open(path, 'w') as f: f.write(content)

if __name__ == "__main__":
    patch_driver()
    print("Done.")
