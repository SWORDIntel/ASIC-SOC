#ifndef __ASIC_TELEMETRY_H__
#define __ASIC_TELEMETRY_H__

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_ALERTS 50
#define MAX_TRAFFIC_LINES 20

typedef struct {
    char timestamp[16];
    char layer[16];
    char message[128];
    int level; // 0: INFO, 1: WARN, 2: CRITICAL
} asic_alert_t;

typedef struct {
    // System Stats
    float host_cpu;
    float host_ram;
    int gpu_temp;
    int asic_load;
    
    // Detection Stats
    int l1_net_count;
    int l2_edr_count;
    int l2_priv_count;
    int l3_hw_count;
    int actual_tensors;
    int tensors_optimized;
    
    // Status Flags
    bool hammer_mode;
    bool vault_locked;
    bool jamming_active;
    
    // Crypto Progress
    float crypto_corr;
    float total_traces;
    
    // Swarm
    int swarm_nodes;
    int swarm_syncs;
    float triang_x;
    float triang_y;
    int triang_conf;

    // Alerts
    asic_alert_t alerts[MAX_ALERTS];
    int alert_count;
    int alert_head;

    // Traffic Streams (Strings)
    char traffic_stream[MAX_TRAFFIC_LINES][128];
    int traffic_head;
    char me_stream[MAX_TRAFFIC_LINES][128];
    int me_head;

} asic_telemetry_t;

extern asic_telemetry_t g_telemetry;

void update_telemetry_stats();
void add_alert(const char* layer, const char* msg, int level);
void add_traffic(const char* msg);
void add_me_traffic(const char* msg);

#ifdef __cplusplus
}
#endif

#endif
