
#define __TARGET_ARCH_x86
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "asic_common.h"

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

// 1. EDR/Stack Sensor
SEC("tp/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx) {
    struct asic_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;
    e->type = EVENT_EXEC;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = (int)bpf_get_current_uid_gid();
    
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);
    
    // Capture Parent UID for Lineage Validation
    struct cred *p_cred = BPF_CORE_READ(task, real_parent, cred);
    e->puid = BPF_CORE_READ(p_cred, uid.val);
    
    e->loginuid = BPF_CORE_READ(task, loginuid.val);
    e->sessionid = BPF_CORE_READ(task, sessionid);
    
    // Check for a controlling terminal (TTY)
    struct signal_struct *signal = BPF_CORE_READ(task, signal);
    struct tty_struct *tty = BPF_CORE_READ(signal, tty);
    e->has_tty = tty ? 1 : 0;
    
    // Get process names
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_probe_read_kernel_str(&e->pcomm, sizeof(e->pcomm), BPF_CORE_READ(task, real_parent, comm));
    
    const char *filename_ptr = (const char *)ctx->args[0];
    bpf_probe_read_user_str(&e->payload, MAX_PAYLOAD, filename_ptr);
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// 2. ME/HECI Sensor (Kprobe)
// Hooks the Intel MEI driver write function
SEC("kprobe/mei_write")
int BPF_KPROBE(trace_mei_write, struct file *file, const char *ubuf, size_t count) {
    struct asic_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;
    e->type = EVENT_ME;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->arg1 = (int)count;
    bpf_probe_read_user(&e->payload, (count < MAX_PAYLOAD) ? count : MAX_PAYLOAD, ubuf);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// 3. Edge/Sideband Sensor (XDP)
SEC("xdp")
int xdp_me_monitor(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    // Safety check for reading first 64 bytes
    if (data + 64 > data_end) return XDP_PASS;

    struct asic_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return XDP_PASS;
    e->type = EVENT_NET;
    
    // Copy 64 bytes of packet data into the payload
    #pragma clang loop unroll(full)
    for (int i = 0; i < 64; i++) {
        e->payload[i] = ((char *)data)[i];
    }
    
    bpf_ringbuf_submit(e, 0);
    
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
