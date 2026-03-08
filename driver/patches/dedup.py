import os
import re

path = 'NVIDIA-Linux-x86_64-390.157/kernel/nvidia-drm/nvidia-drm-drv.c'
if os.path.exists(path):
    with open(path, 'r') as f:
        content = f.read()
    
    # Define the patterns to remove (only the duplicates)
    # The pattern for the client registration block
    client_reg_block = """#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
    /* Register a DRM client for receiving hotplug events */
    struct drm_client_dev *client = kzalloc(sizeof(*client), GFP_KERNEL);
    if (client == NULL || drm_client_init(dev, client,
        "nv-hotplug-helper", &nv_hotplug_helper_client_funcs)) {
        printk(KERN_WARNING "Failed to initialize the nv-hotplug-helper DRM client"
            " (ensure DRM kernel mode setting is enabled via nvidia-drm.modeset=1).\n");
        goto failed_drm_client_init;
    }

    drm_client_register(client);
    pr_info("Registered the nv-hotplug-helper DRM client.\\n");
#endif"""

    # The pattern for the error label block
    error_label_block = """#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
failed_drm_client_init:

    kfree(client);
    drm_dev_unregister(dev);

#endif"""

    # We want to keep ONLY ONE occurrence.
    # Find all occurrences
    reg_matches = [m.start() for m in re.finditer(re.escape(client_reg_block), content)]
    if len(reg_matches) > 1:
        # Keep the first one, remove the others
        # Actually, let's just replace ALL occurrences with ONE occurrence.
        content = content.replace(client_reg_block, "TEMP_REG_BLOCK")
        content = content.replace("TEMP_REG_BLOCK", client_reg_block, 1)
        content = content.replace("TEMP_REG_BLOCK", "")

    label_matches = [m.start() for m in re.finditer(re.escape(error_label_block), content)]
    if len(label_matches) > 1:
        content = content.replace(error_label_block, "TEMP_LABEL_BLOCK")
        content = content.replace("TEMP_LABEL_BLOCK", error_label_block, 1)
        content = content.replace("TEMP_LABEL_BLOCK", "")

    with open(path, 'w') as f:
        f.write(content)
    print("Deduplication complete.")
