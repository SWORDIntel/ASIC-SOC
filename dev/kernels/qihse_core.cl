
#define VECTOR_DIMS 160

// 1. QIHSE Vector Core
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

// 2. KP14 Malware Core
__kernel void kp14_correlation_core(__global const unsigned long *payload, __global const unsigned long *sigs, __global int *matches, const int num_sigs) {
    int gid = get_global_id(0);
    unsigned long data = payload[gid];
    for (int i = 0; i < num_sigs; i++) { if (data == sigs[i]) atomic_inc(&matches[i]); }
}

// 3. SPECTRA Intel Core
__kernel void spectra_intel_core(__global const char *stream, __global const char *keys, __global int *alerts, const int k_len, const int n_keys) {
    int gid = get_global_id(0);
    for (int k = 0; k < n_keys; k++) {
        int m = 1; __global const char *t = &keys[k * k_len];
        for (int i = 0; i < k_len; i++) { if (stream[gid + i] != t[i]) { m = 0; break; } }
        if (m) atomic_inc(&alerts[k]);
    }
}

// 4. L6 ME Berserker Core (Persistent DPA Accumulator)
// Accumulates sums across millions of traces to extract keys from noise.
__kernel void me_berserker_core(
    __global const float *pmc_trace,
    __global float *sum_x,   // Persistent VRAM: Sum of traces
    __global float *sum_xy,  // Persistent VRAM: Sum of trace * hypothesis
    __global float *sum_x2,  // Persistent VRAM: Sum of trace^2
    const int trace_len,
    const int num_hypotheses)
{
    int gid = get_global_id(0);
    if (gid >= num_hypotheses) return;

    for (int i = 0; i < trace_len; i++) {
        float x = pmc_trace[i];
        float y = (float)((gid ^ i) & 1); // Advanced leak model hypothesis
        
        sum_x[gid] += x;
        sum_xy[gid] += x * y;
        sum_x2[gid] += x * x;
    }
}

// 4b. ME Hammer Core (Vectorized / High Intensity)
__kernel void me_hammer_core(
    __global const float4 *pmc_trace_v,
    __global float4 *sum_x_v,
    __global float4 *sum_xy_v,
    __global float4 *sum_x2_v,
    const int v_trace_len,
    const int num_v_hypotheses)
{
    int gid = get_global_id(0);
    if (gid >= num_v_hypotheses) return;

    for (int i = 0; i < v_trace_len; i++) {
        float4 x = pmc_trace_v[i];
        // SIMD hypothesis: 4 parallel hypotheses per thread
        float4 y = (float4)((float)((gid*4 ^ i) & 1), 
                           (float)((gid*4+1 ^ i) & 1),
                           (float)((gid*4+2 ^ i) & 1),
                           (float)((gid*4+3 ^ i) & 1));
        
        sum_x_v[gid] += x;
        sum_xy_v[gid] += x * y;
        sum_x2_v[gid] += x * x;
    }
}

// 5. L6 Correlation Finalizer
__kernel void me_correlation_finalizer(
    __global const float *sum_x,
    __global const float *sum_xy,
    __global const float *sum_x2,
    __global float *final_scores,
    const float n_total,
    const int num_hypotheses)
{
    int gid = get_global_id(0);
    if (gid >= num_hypotheses) return;

    float sx = sum_x[gid];
    float sxy = sum_xy[gid];
    float sx2 = sum_x2[gid];
    
    // Pearson model constants for binary leakage
    float sy = n_total / 2.0f;
    float sy2 = n_total / 2.0f;

    float num = (n_total * sxy) - (sx * sy);
    float den = sqrt((n_total * sx2 - (sx * sx)) * (n_total * sy2 - (sy * sy)));

    final_scores[gid] = (den != 0.0f) ? fabs(num / den) : 0.0f;
}

// ... (Other standard cores: priv, me_sentry, entropy, code_intel remain)
__kernel void priv_enforcer(const int old_uid, const int new_uid, __global int *alert) { if (old_uid != 0 && new_uid == 0) *alert = 1; }
__kernel void me_sentry_core(__global const char *p, __global int *a) {
    int gid = get_global_id(0); const char s[] = {0x01, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    int m = 1; for(int i=0; i<8; i++) { if(p[gid*8+i] != s[i]) { m=0; break; } } if(m) *a = 1;
}
__kernel void qihse_entropy_analyzer(__global const float *s, __global float *a, const int w) {
    int gid = get_global_id(0); float sum = 0.0f; for (int i = 0; i < w; i++) sum += s[gid + i];
    float m = sum / w; float v = 0.0f; for (int i = 0; i < w; i++) { float d = s[gid+i]-m; v += d*d; } a[gid] = v/w;
}
__kernel void qihse_hebbian_update(__global float *db, __global const float *q, const int b, const float lr) {
    int i = get_global_id(0); if (i >= 160) return;
    int o = b * 160 + i; db[o] = db[o] + (lr * (q[i] - db[o]));
}
__kernel void code_intelligence_core(__global const float *cv, __global const float *sv, __global float *s, const int n) {
    int gid = get_global_id(0); if (gid >= n) return;
    float d=0, nc=0, ns=0; for (int i=0; i<160; i++) { float c=cv[gid*160+i], v=sv[i]; d+=c*v; nc+=c*c; ns+=v*v; }
    s[gid] = (nc>0 && ns>0) ? d/(sqrt(nc)*sqrt(ns)) : 0;
}
