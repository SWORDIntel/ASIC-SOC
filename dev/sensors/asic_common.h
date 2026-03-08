
#ifndef __ASIC_COMMON_H__
#define __ASIC_COMMON_H__

#define EVENT_EXEC  1
#define EVENT_MEM   2
#define EVENT_NET   3
#define EVENT_PRIV  4
#define EVENT_STACK 5
#define EVENT_ME    6  // Intel ME/CSME Activity
#define EVENT_RF    10 // L4 EW/Jamming

#define MAX_PAYLOAD 256

struct asic_event {
    int type;
    int pid;
    int uid; 
    int gid;
    char comm[16];
    int arg1; 
    char payload[MAX_PAYLOAD];
    int node_id;
    float rf_signals[10];
};

#endif
