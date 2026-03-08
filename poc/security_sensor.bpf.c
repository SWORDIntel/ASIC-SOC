
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

struct security_event {
    int pid;
    char comm[16];
    int requested_prot;
    int type; // 1 = mprotect, 2 = mmap
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

SEC("tp/syscalls/sys_enter_mprotect")
int trace_mprotect(void *ctx) {
    struct security_event *e;
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    
    // mprotect argument 'prot' is at offset 24 in many kernels
    bpf_probe_read_kernel(&e->requested_prot, sizeof(int), ctx + 24);
    e->type = 1;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_mmap")
int trace_mmap(void *ctx) {
    struct security_event *e;
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    
    // mmap argument 'prot' is at offset 24 or similar
    bpf_probe_read_kernel(&e->requested_prot, sizeof(int), ctx + 24);
    e->type = 2;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
