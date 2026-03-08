
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "edr_common.h"

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

SEC("tp/syscalls/sys_enter_execve")
int trace_execve(void *ctx) {
    struct event *e;
    
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    
    // Manual offset for sys_enter_execve filename
    // Offset is usually 16 or 24 depending on kernel
    const char *cmd_ptr;
    bpf_probe_read_kernel(&cmd_ptr, sizeof(cmd_ptr), ctx + 16); 

    if (cmd_ptr) {
        bpf_probe_read_user_str(&e->cmdline, sizeof(e->cmdline), cmd_ptr);
    }
    
    e->timestamp = bpf_ktime_get_ns();
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
