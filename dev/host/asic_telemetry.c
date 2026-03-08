#include "asic_telemetry.h"
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/sysinfo.h>

asic_telemetry_t g_telemetry = {0};

void update_telemetry_stats() {
    struct sysinfo info;
    if (sysinfo(&info) == 0) {
        // Simple CPU load approximation from loads[0]
        g_telemetry.host_cpu = (float)info.loads[0] / (1 << SI_LOAD_SHIFT) * 100.0f / 8.0f; // Assuming 8 cores
        if (g_telemetry.host_cpu > 100.0f) g_telemetry.host_cpu = 100.0f;
        
        g_telemetry.host_ram = (float)(info.totalram - info.freeram) / info.totalram * 100.0f;
    }
}

void add_alert(const char* layer, const char* msg, int level) {
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    
    asic_alert_t *a = &g_telemetry.alerts[g_telemetry.alert_head];
    strftime(a->timestamp, 16, "%H:%M:%S", t);
    strncpy(a->layer, layer, 15);
    strncpy(a->message, msg, 127);
    a->level = level;
    
    g_telemetry.alert_head = (g_telemetry.alert_head + 1) % MAX_ALERTS;
    if (g_telemetry.alert_count < MAX_ALERTS) g_telemetry.alert_count++;
}

void add_traffic(const char* msg) {
    strncpy(g_telemetry.traffic_stream[g_telemetry.traffic_head], msg, 127);
    g_telemetry.traffic_head = (g_telemetry.traffic_head + 1) % MAX_TRAFFIC_LINES;
}

void add_me_traffic(const char* msg) {
    strncpy(g_telemetry.me_stream[g_telemetry.me_head], msg, 127);
    g_telemetry.me_head = (g_telemetry.me_head + 1) % MAX_TRAFFIC_LINES;
}
