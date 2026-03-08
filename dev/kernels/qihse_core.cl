
#define VECTOR_DIMS 160

// 1. QIHSE Vector Core (Existing)
__kernel void qihse_vector_search(__global const float *db, __global const float *query, __global float *scores, const int num_db) {
    int gid = get_global_id(0);
    if (gid >= num_db) return;
    float dot = 0.0f, na = 0.0f, nb = 0.0f;
    for (int i = 0; i < VECTOR_DIMS; i++) {
        float a = db[gid * VECTOR_DIMS + i], b = query[i];
        dot += a * b; na += a * a; nb += b * b;
    }
    scores[gid] = (na > 0 && nb > 0) ? dot / (sqrt(na) * sqrt(nb)) : 0.0f;
}

// 2. KP14 Malware Correlation Core
// Scans payload against known malware artifact hashes/signatures
__kernel void kp14_correlation_core(
    __global const unsigned long *payload,
    __global const unsigned long *malware_sigs,
    __global int *matches,
    const int num_sigs)
{
    int gid = get_global_id(0);
    unsigned long data = payload[gid];
    for (int i = 0; i < num_sigs; i++) {
        if (data == malware_sigs[i]) {
            atomic_inc(&matches[i]);
        }
    }
}

// 3. SPECTRA OSINT Core
// SIMD keyword matching for Telegram/OSINT intel streams
__kernel void spectra_intel_core(
    __global const char *intel_stream,
    __global const char *keywords,
    __global int *intel_alerts,
    const int keyword_len,
    const int num_keywords)
{
    int gid = get_global_id(0); // Thread per char in stream
    for (int k = 0; k < num_keywords; k++) {
        int match = 1;
        __global const char *target = &keywords[k * keyword_len];
        for (int i = 0; i < keyword_len; i++) {
            if (intel_stream[gid + i] != target[i]) {
                match = 0; break;
            }
        }
        if (match) atomic_inc(&intel_alerts[k]);
    }
}

// ... (Other cores: priv_enforcer, me_sentry, entropy analyzer remain)
__kernel void priv_enforcer(const int old_uid, const int new_uid, __global int *alert) {
    if (old_uid != 0 && new_uid == 0) *alert = 1;
}

__kernel void me_sentry_core(__global const char *me_payload, __global int *anomaly_score) {
    int gid = get_global_id(0);
    const char me_exploit_sig[] = {0x01, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    int match = 1;
    for(int i=0; i<8; i++) { if(me_payload[gid * 8 + i] != me_exploit_sig[i]) { match = 0; break; } }
    if(match) *anomaly_score = 1;
}

__kernel void qihse_entropy_analyzer(__global const float *pmc_stream, __global float *anomaly_scores, const int window_size) {
    int gid = get_global_id(0);
    float sum = 0.0f;
    for (int i = 0; i < window_size; i++) sum += pmc_stream[gid + i];
    float mean = sum / window_size;
    float variance = 0.0f;
    for (int i = 0; i < window_size; i++) {
        float diff = pmc_stream[gid + i] - mean;
        variance += diff * diff;
    }
    anomaly_scores[gid] = variance / window_size;
}

__kernel void rf_spectrum_analyzer(__global const float *rf_signals_current, __global const float *rf_signals_baseline, __global float *ew_anomaly_score, const int num_channels) {
    int gid = get_global_id(0); if(gid != 0) return;
    int deafened = 0;
    for(int i=0; i<num_channels; i++) { if(rf_signals_baseline[i] > -90.0f && rf_signals_current[i] <= -100.0f) deafened++; }
    *ew_anomaly_score = (deafened >= (num_channels / 2)) ? 1.0f : 0.0f;
}
