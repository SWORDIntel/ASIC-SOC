#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "asic_common.h"

#define EDR_AF_INET 2
#define EDR_AF_INET6 10

struct trace_event_raw_sys_enter {
    unsigned long long unused;
    unsigned long long id;
    unsigned long long args[6];
};

struct edr_sockaddr_in {
    unsigned short family;
    unsigned short port;
    unsigned int addr;
    unsigned char pad[8];
};

struct edr_sockaddr_in6 {
    unsigned short family;
    unsigned short port;
    unsigned int flowinfo;
    unsigned char addr[16];
    unsigned int scope_id;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

static __always_inline void fill_task_identity(struct edr_event *e) {
    unsigned long long pid_tgid = bpf_get_current_pid_tgid();
    unsigned long long uid_gid = bpf_get_current_uid_gid();

    e->pid = pid_tgid >> 32;
    e->tid = (unsigned int)pid_tgid;
    e->uid = (unsigned int)uid_gid;
    e->gid = uid_gid >> 32;
    e->timestamp_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
}

SEC("tp/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx) {
    struct edr_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    __builtin_memset(e, 0, sizeof(*e));
    fill_task_identity(e);
    e->type = EDR_EVENT_EXEC;
    e->ppid = 0;

    const char *filename = (const char *)ctx->args[0];
    bpf_probe_read_user_str(&e->target, sizeof(e->target), filename);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_mprotect")
int trace_mprotect(struct trace_event_raw_sys_enter *ctx) {
    struct edr_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    __builtin_memset(e, 0, sizeof(*e));
    fill_task_identity(e);
    e->type = EDR_EVENT_MPROTECT;
    e->prot = (__u32)ctx->args[2];

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_mmap")
int trace_mmap(struct trace_event_raw_sys_enter *ctx) {
    struct edr_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    __builtin_memset(e, 0, sizeof(*e));
    fill_task_identity(e);
    e->type = EDR_EVENT_MMAP;
    e->prot = (__u32)ctx->args[2];
    e->flags = (__u32)ctx->args[3];

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx) {
    struct edr_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    __builtin_memset(e, 0, sizeof(*e));
    fill_task_identity(e);
    e->type = EDR_EVENT_OPENAT;
    e->flags = (__u32)ctx->args[2];

    const char *filename = (const char *)ctx->args[1];
    bpf_probe_read_user_str(&e->target, sizeof(e->target), filename);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_connect")
int trace_connect(struct trace_event_raw_sys_enter *ctx) {
    const void *uaddr = (const void *)ctx->args[1];
    unsigned short family = 0;

    if (!uaddr) {
        return 0;
    }

    if (bpf_probe_read_user(&family, sizeof(family), uaddr) != 0) {
        return 0;
    }

    if (family != EDR_AF_INET && family != EDR_AF_INET6) {
        return 0;
    }

    struct edr_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    __builtin_memset(e, 0, sizeof(*e));
    fill_task_identity(e);
    e->type = EDR_EVENT_CONNECT;
    e->net_family = family;

    if (family == EDR_AF_INET) {
        struct edr_sockaddr_in sin = {};
        if (bpf_probe_read_user(&sin, sizeof(sin), uaddr) == 0) {
            e->net_port = sin.port;
            e->net_addr_v4 = sin.addr;
        }
    } else {
        struct edr_sockaddr_in6 sin6 = {};
        if (bpf_probe_read_user(&sin6, sizeof(sin6), uaddr) == 0) {
            e->net_port = sin6.port;
            __builtin_memcpy(e->net_addr_v6, sin6.addr, sizeof(e->net_addr_v6));
        }
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
