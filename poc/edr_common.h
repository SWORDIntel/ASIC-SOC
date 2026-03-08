
#ifndef __EDR_COMMON_H__
#define __EDR_COMMON_H__

#define MAX_CMDLINE_SIZE 256

struct event {
    int pid;
    char comm[16];
    char cmdline[MAX_CMDLINE_SIZE];
    unsigned long long timestamp;
};

#endif
