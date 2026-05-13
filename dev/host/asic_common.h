
#ifndef __ASIC_COMMON_H__
#define __ASIC_COMMON_H__

#include <stdint.h>

enum edr_event_type {
    EDR_EVENT_EXEC = 1,
    EDR_EVENT_MPROTECT = 2,
    EDR_EVENT_MMAP = 3,
    EDR_EVENT_OPENAT = 4,
    EDR_EVENT_CONNECT = 5,
};

#define EDR_MAX_TARGET 256

struct edr_event {
    uint32_t type;
    uint32_t pid;
    uint32_t tid;
    uint32_t ppid;
    uint32_t uid;
    uint32_t gid;
    uint32_t flags;
    uint32_t prot;
    uint32_t net_family;
    uint32_t net_addr_v4;
    uint16_t net_port;
    uint8_t net_addr_v6[16];
    uint8_t reserved[6];
    uint64_t timestamp_ns;
    char comm[16];
    char target[EDR_MAX_TARGET];
};

#endif
