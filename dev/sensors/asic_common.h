
#ifndef __ASIC_COMMON_H__
#define __ASIC_COMMON_H__

enum edr_event_type {
    EDR_EVENT_EXEC = 1,
    EDR_EVENT_MPROTECT = 2,
    EDR_EVENT_MMAP = 3,
    EDR_EVENT_OPENAT = 4,
    EDR_EVENT_CONNECT = 5,
};

#define EDR_MAX_TARGET 256

struct edr_event {
    unsigned int type;
    unsigned int pid;
    unsigned int tid;
    unsigned int ppid;
    unsigned int uid;
    unsigned int gid;
    unsigned int flags;
    unsigned int prot;
    unsigned int net_family;
    unsigned int net_addr_v4;
    unsigned short net_port;
    unsigned char net_addr_v6[16];
    unsigned char reserved[6];
    unsigned long long timestamp_ns;
    char comm[16];
    char target[EDR_MAX_TARGET];
};

#endif
