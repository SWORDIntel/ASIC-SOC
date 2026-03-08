#define VECTOR_DIMS 160

// 1. QIHSE Vector Core - Optimized for Fermi (Constant Cache + Register Accumulation)
__kernel void qihse_vector_search(
    __global const float4 *db, 
    __constant float4 *query, 
    __global float *scores, 
    const int num_db) 
{
    int gid = get_global_id(0);
    if (gid >= num_db) return;

    float dot = 0.0f;
    float na = 0.0f;
    float nb = 0.0f;

    #pragma unroll 4
    for (int i = 0; i < 40; i++) {
        float4 a = db[gid * 40 + i];
        float4 b = query[i];
        dot += a.x * b.x + a.y * b.y + a.z * b.z + a.w * b.w;
        na  += a.x * a.x + a.y * a.y + a.z * a.z + a.w * a.w;
        nb  += b.x * b.x + b.y * b.y + b.z * b.z + b.w * b.w;
    }
    scores[gid] = (na > 0 && nb > 0) ? dot / (native_sqrt(na) * native_sqrt(nb)) : 0.0f;
}

// 2. L6 ME Berserker Core - Optimized
__kernel void me_berserker_core(
    __global const float *pmc_trace,
    __global float *sum_x,
    __global float *sum_xy,
    __global float *sum_x2,
    const int trace_len,
    const int num_hypotheses)
{
    int gid = get_global_id(0);
    if (gid >= num_hypotheses) return;

    float sx = 0.0f;
    float sxy = 0.0f;
    float sx2 = 0.0f;

    for (int i = 0; i < trace_len; i++) {
        float x = pmc_trace[i];
        float y = (float)((gid ^ i) & 1);
        sx += x;
        sxy += x * y;
        sx2 += x * x;
    }
    
    sum_x[gid] += sx;
    sum_xy[gid] += sxy;
    sum_x2[gid] += sx2;
}

// 3. L6 ME Hammer Core - Vectorized
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

    float4 sx = (float4)0.0f;
    float4 sxy = (float4)0.0f;
    float4 sx2 = (float4)0.0f;

    for (int i = 0; i < v_trace_len; i++) {
        float4 x = pmc_trace_v[i];
        float4 y = (float4)((float)((gid*4 ^ i) & 1), 
                           (float)((gid*4+1 ^ i) & 1),
                           (float)((gid*4+2 ^ i) & 1),
                           (float)((gid*4+3 ^ i) & 1));
        sx += x;
        sxy += x * y;
        sx2 += x * x;
    }
    sum_x_v[gid] += sx;
    sum_xy_v[gid] += sxy;
    sum_x2_v[gid] += sx2;
}

// 4. L6 Correlation Finalizer
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
    float sy = n_total / 2.0f;
    float sy2 = n_total / 2.0f;

    float num = (n_total * sxy) - (sx * sy);
    float den = native_sqrt((n_total * sx2 - (sx * sx)) * (n_total * sy2 - (sy * sy)));
    final_scores[gid] = (den != 0.0f) ? fabs(num / den) : 0.0f;
}

// 5. L3 Entropy Analyzer (Cache Side-Channel Detection)
__kernel void qihse_entropy_analyzer(__global const float *s, __global float *a, const int w) {
    int gid = get_global_id(0);
    float sum = 0.0f; 
    for (int i = 0; i < w; i++) sum += s[gid + i];
    float m = sum / w; 
    float v = 0.0f; 
    for (int i = 0; i < w; i++) { float d = s[gid+i]-m; v += d*d; } 
    a[gid] = v/w;
}

__kernel void priv_enforcer(const int old_uid, const int new_uid, __global int *alert) { if (old_uid != 0 && new_uid == 0) *alert = 1; }
__kernel void me_sentry_core(__global const char *p, __global int *a) {
    int gid = get_global_id(0); const char s[] = {0x01, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    int m = 1; for(int i=0; i<8; i++) { if(p[gid*8+i] != s[i]) { m=0; break; } } if(m) *a = 1;
}
__kernel void qihse_hebbian_update(__global float *db, __global const float *q, const int b, const float lr) {
    int i = get_global_id(0); if (i >= 160) return;
    int o = b * 160 + i; db[o] = db[o] + (lr * (q[i] - db[o]));
}

__kernel void code_intelligence_core(__global const float4 *cv, __global const float4 *sv, __global float *s, const int n) {
    int gid = get_global_id(0); if (gid >= n) return;
    float d=0, nc=0, ns=0; 
    for (int i=0; i<40; i++) { 
        float4 c=cv[gid*40+i], v=sv[i]; 
        d += c.x*v.x + c.y*v.y + c.z*v.z + c.w*v.w;
        nc += c.x*c.x + c.y*c.y + c.z*c.z + c.w*c.w;
        ns += v.x*v.x + v.y*v.y + v.z*v.z + v.w*v.w;
    }
    s[gid] = (nc>0 && ns>0) ? d/(native_sqrt(nc)*native_sqrt(ns)) : 0;
}

__kernel void blackbox_append(__global char *buffer, __global const char *data, const int head, const int buffer_size, const int data_size) {
    int gid = get_global_id(0);
    if (gid >= data_size) return;
    buffer[(head + gid) % buffer_size] = data[gid];
}
