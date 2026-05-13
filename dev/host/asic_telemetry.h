#ifndef __ASIC_TELEMETRY_H__
#define __ASIC_TELEMETRY_H__

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_ALERTS 64
#define MAX_RECENT_EVENTS 32
#define MAX_EVENT_MESSAGE 512

typedef struct {
    char timestamp[16];
    char source[16];
    char message[MAX_EVENT_MESSAGE];
    int level; /* 0: INFO, 1: WARN, 2: CRITICAL */
} asic_alert_t;

typedef struct {
    float host_cpu;
    float host_ram;
    int exec_events;
    int mem_events;
    int file_events;
    int net_events;
    int suspicious_events;

    asic_alert_t alerts[MAX_ALERTS];
    int alert_count;
    int alert_head;

    char recent_events[MAX_RECENT_EVENTS][MAX_EVENT_MESSAGE];
    int recent_head;
} asic_telemetry_t;

extern asic_telemetry_t g_telemetry;

void update_telemetry_stats(void);
void add_alert(const char *source, const char *msg, int level);
void add_traffic(const char *msg);

#ifdef __cplusplus
}
#endif

#endif
