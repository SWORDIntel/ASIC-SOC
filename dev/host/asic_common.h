
#ifndef __ASIC_COMMON_H__
#define __ASIC_COMMON_H__

#define EVENT_EXEC    1
#define EVENT_MEM     2
#define EVENT_NET     3
#define EVENT_PRIV    4
#define EVENT_STACK   5
#define EVENT_ME      6
#define EVENT_MALWARE 7 // KP14 Core
#define EVENT_INTEL   8 // SPECTRA Core

#define MAX_PAYLOAD 256

struct asic_event {
    int type;
    int pid;
    int uid;
    int gid;
    char comm[16];
    int arg1; 
    char payload[MAX_PAYLOAD];
};

#endif
