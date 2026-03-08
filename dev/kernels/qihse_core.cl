#define VECTOR_DIMS 160
#define LWS 256

// 1. QIHSE Vector Core - Optimized for Fermi (Shared Memory Tiling + Register Accumulation)
__kernel void qihse_vector_search(
    __global const float4 *db, 
    __global const float4 *query, 
    __global float *scores, 
    const int num_db) 
{
    __local float4 l_query[40]; // 160 floats / 4 = 40 float4s
    int lid = get_local_id(0);
    int gid = get_global_id(0);
    int lsize = get_local_size(0);

    // Stage query vector in Shared Memory
    for (int i = lid; i < 40; i += lsize) {
        l_query[i] = query[i];
    }
    barrier(CLK_LOCAL_MEM_FENCE);

    if (gid >= num_db) return;

    // Register blocking for accumulation
    float dot = 0.0f;
    float na = 0.0f;
    float nb = 0.0f;

    #pragma unroll 10
    for (int i = 0; i < 40; i++) {
        float4 a = db[gid * 40 + i];
        float4 b = l_query[i];
        
        dot += a.x * b.x + a.y * b.y + a.z * b.z + a.w * b.w;
        na  += a.x * a.x + a.y * a.y + a.z * a.z + a.w * a.w;
        nb  += b.x * b.x + b.y * b.y + b.z * b.z + b.w * b.w;
    }
    
    scores[gid] = (na > 0.0f && nb > 0.0f) ? dot / (native_sqrt(na) * native_sqrt(nb)) : 0.0f;
}

// 2. L6 ME Berserker Core - Optimized with Local Memory Tiling
__kernel void me_berserker_core(
    __global const float *pmc_trace,
    __global float *sum_x,
    __global float *sum_xy,
    __global float *sum_x2,
    const int trace_len,
    const int num_hypotheses)
{
    int gid = get_global_id(0);
    int lid = get_local_id(0);
    int lsize = get_local_size(0);

    float sx = 0.0f;
    float sxy = 0.0f;
    float sx2 = 0.0f;

    __local float l_trace[LWS];

    for (int i = 0; i < trace_len; i += lsize) {
        int chunk_size = min(lsize, trace_len - i);
        if (lid < chunk_size) {
            l_trace[lid] = pmc_trace[i + lid];
        }
        barrier(CLK_LOCAL_MEM_FENCE);

        #pragma unroll 16
        for (int j = 0; j < chunk_size; j++) {
            float x = l_trace[j];
            float y = (float)((gid ^ (i + j)) & 1);
            sx += x;
            sxy += x * y;
            sx2 += x * x;
        }
        barrier(CLK_LOCAL_MEM_FENCE);
    }
    
    if (gid < num_hypotheses) {
        sum_x[gid] += sx;
        sum_xy[gid] += sxy;
        sum_x2[gid] += sx2;
    }
}

// 3. L6 ME Hammer Core - Vectorized with Shared Memory Tiling
__kernel void me_hammer_core(
    __global const float4 *pmc_trace_v,
    __global float4 *sum_x_v,
    __global float4 *sum_xy_v,
    __global float4 *sum_x2_v,
    const int v_trace_len,
    const int num_v_hypotheses)
{
    int gid = get_global_id(0);
    int lid = get_local_id(0);
    int lsize = get_local_size(0);

    float4 sx = (float4)0.0f;
    float4 sxy = (float4)0.0f;
    float4 sx2 = (float4)0.0f;

    __local float4 l_trace_v[LWS];

    for (int i = 0; i < v_trace_len; i += lsize) {
        int chunk_size = min(lsize, v_trace_len - i);
        if (lid < chunk_size) {
            l_trace_v[lid] = pmc_trace_v[i + lid];
        }
        barrier(CLK_LOCAL_MEM_FENCE);

        #pragma unroll 8
        for (int j = 0; j < chunk_size; j++) {
            float4 x = l_trace_v[j];
            int base_idx = i + j;
            float4 y = (float4)((float)((gid*4 ^ base_idx) & 1), 
                               (float)((gid*4+1 ^ base_idx) & 1),
                               (float)((gid*4+2 ^ base_idx) & 1),
                               (float)((gid*4+3 ^ base_idx) & 1));
            sx += x;
            sxy += x * y;
            sx2 += x * x;
        }
        barrier(CLK_LOCAL_MEM_FENCE);
    }
    
    if (gid < num_v_hypotheses) {
        sum_x_v[gid] += sx;
        sum_xy_v[gid] += sxy;
        sum_x2_v[gid] += sx2;
    }
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
    float sy = n_total * 0.5f;
    float sy2 = n_total * 0.5f;

    float num = (n_total * sxy) - (sx * sy);
    float den = native_sqrt((n_total * sx2 - (sx * sx)) * (n_total * sy2 - (sy * sy)));
    final_scores[gid] = (den != 0.0f) ? fabs(num / den) : 0.0f;
}

// 5. L3 Entropy Analyzer (Cache Side-Channel Detection) - Optimized with Shared Memory
__kernel void qihse_entropy_analyzer(__global const float *s, __global float *a, const int w) {
    int gid = get_global_id(0);
    int lid = get_local_id(0);
    int lsize = get_local_size(0);
    
    // We need 'w' extra elements in local memory for the sliding window
    // PMC_WINDOW is 100, w is 50.
    __local float l_s[LWS + 100]; 
    
    // Cooperative load
    for (int i = lid; i < lsize + w; i += lsize) {
        l_s[i] = s[get_group_id(0) * lsize + i];
    }
    barrier(CLK_LOCAL_MEM_FENCE);

    float sum = 0.0f; 
    #pragma unroll 10
    for (int i = 0; i < w; i++) sum += l_s[lid + i];
    float m = sum / w; 
    
    float v = 0.0f; 
    #pragma unroll 10
    for (int i = 0; i < w; i++) { 
        float d = l_s[lid + i] - m; 
        v += d * d; 
    } 
    a[gid] = v / w;
}

__kernel void priv_enforcer(const int uid, const int loginuid, const int has_tty, const int puid, __global int *alert) { 
    if (uid == 0) {
        if (has_tty == 1 && loginuid != -1) {
            *alert = 2; // AUTHORIZED
        } 
        else if (has_tty == 0 && puid != 0) {
            *alert = 1; // CRITICAL UNAUTHORIZED
        }
        else {
            *alert = 3; // SYSTEM_SERVICE
        }
    }
}

__kernel void me_sentry_core(__global const char *p, __global int *a) {
    int gid = get_global_id(0); 
    const char s[] = {0x01, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    int m = 1; 
    #pragma unroll
    for(int i=0; i<8; i++) { 
        if(p[gid*8+i] != s[i]) { m=0; break; } 
    } 
    if(m) *a = 1;
}

__kernel void qihse_hebbian_update(__global float *db, __global const float *q, const int b, const float lr) {
    int i = get_global_id(0); 
    if (i >= 160) return;
    int o = b * 160 + i; 
    db[o] = db[o] + (lr * (q[i] - db[o]));
}

__kernel void code_intelligence_core(__global const float4 *cv, __global const float4 *sv, __global float *s, const int n) {
    __local float4 l_sv[40];
    int lid = get_local_id(0);
    int lsize = get_local_size(0);
    int gid = get_global_id(0);

    for (int i = lid; i < 40; i += lsize) {
        l_sv[i] = sv[i];
    }
    barrier(CLK_LOCAL_MEM_FENCE);

    if (gid >= n) return;
    
    float d=0.0f, nc=0.0f, ns=0.0f; 
    #pragma unroll 10
    for (int i=0; i<40; i++) { 
        float4 c = cv[gid*40+i];
        float4 v = l_sv[i]; 
        d  += c.x*v.x + c.y*v.y + c.z*v.z + c.w*v.w;
        nc += c.x*c.x + c.y*c.y + c.z*c.z + c.w*c.w;
        ns += v.x*v.x + v.y*v.y + v.z*v.z + v.w*v.w;
    }
    s[gid] = (nc > 0.0f && ns > 0.0f) ? d / (native_sqrt(nc) * native_sqrt(ns)) : 0.0f;
}

__kernel void blackbox_append(__global char *buffer, __global const char *data, const int head, const int buffer_size, const int data_size) {
    int gid = get_global_id(0);
    if (gid >= data_size) return;
    buffer[(head + gid) % buffer_size] = data[gid];
}
