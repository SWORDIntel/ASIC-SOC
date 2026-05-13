#include "asic_telemetry.h"

#include <stdio.h>
#include <string.h>
#include <sys/sysinfo.h>
#include <time.h>

asic_telemetry_t g_telemetry = {0};

void update_telemetry_stats(void) {
    struct sysinfo info;
    if (sysinfo(&info) != 0 || info.totalram == 0) {
        return;
    }

    g_telemetry.host_cpu = (float)info.loads[0] / (1 << SI_LOAD_SHIFT) * 100.0f / 8.0f;
    if (g_telemetry.host_cpu > 100.0f) {
        g_telemetry.host_cpu = 100.0f;
    }

    g_telemetry.host_ram = (float)(info.totalram - info.freeram) / info.totalram * 100.0f;
}

void add_alert(const char *source, const char *msg, int level) {
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    asic_alert_t *a = &g_telemetry.alerts[g_telemetry.alert_head];

    if (t) {
        strftime(a->timestamp, sizeof(a->timestamp), "%H:%M:%S", t);
    } else {
        snprintf(a->timestamp, sizeof(a->timestamp), "--:--:--");
    }

    snprintf(a->source, sizeof(a->source), "%s", source);
    snprintf(a->message, sizeof(a->message), "%s", msg);
    a->level = level;

    g_telemetry.alert_head = (g_telemetry.alert_head + 1) % MAX_ALERTS;
    if (g_telemetry.alert_count < MAX_ALERTS) {
        g_telemetry.alert_count++;
    }
}

void add_traffic(const char *msg) {
    snprintf(g_telemetry.recent_events[g_telemetry.recent_head],
             sizeof(g_telemetry.recent_events[g_telemetry.recent_head]),
             "%s", msg);
    g_telemetry.recent_head = (g_telemetry.recent_head + 1) % MAX_RECENT_EVENTS;
}
