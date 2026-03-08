
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <CL/cl.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <net/if.h>
#include <linux/if_link.h>
#include "asic_common.h"

// ASIC Configuration
#define DB_SIZE 800
#define VECTOR_DIMS 160
#define NUM_MALWARE_SIGS 10
#define INTEL_KEYWORD_LEN 16
#define INTEL_KEYWORD_COUNT 4

// OpenCL Globals
cl_context ctx;
cl_command_queue cmd_q;
cl_kernel vec_k, super_k, entropy_k, priv_k, me_k, rf_k, mal_k, intel_k;
cl_mem db_vectors_mem, dev_masks, dev_mal_sigs, dev_intel_keywords;

unsigned long mal_sigs[NUM_MALWARE_SIGS] = { 0xDEADC0DE, 0xBEEFBABE, 0x1337C0DE };
const char intel_keywords[INTEL_KEYWORD_COUNT][INTEL_KEYWORD_LEN] = { "0day            ", "exploit         ", "cve-2026        ", "payload         " };

static int stop = 0;
void sig_handler(int sig) { stop = 1; }

void init_asic() {
    cl_platform_id platforms[4]; cl_uint n_plat;
    clGetPlatformIDs(4, platforms, &n_plat);
    cl_platform_id plat = NULL;
    for(cl_uint i=0; i<n_plat; i++){
        char name[128]; clGetPlatformInfo(platforms[i], CL_PLATFORM_NAME, 128, name, NULL);
        if(strstr(name, "NVIDIA")) { plat = platforms[i]; break; }
    }
    cl_device_id dev; clGetDeviceIDs(plat, CL_DEVICE_TYPE_GPU, 1, &dev, NULL);
    cl_int err;
    ctx = clCreateContext(NULL, 1, &dev, NULL, NULL, &err);
    cmd_q = clCreateCommandQueue(ctx, dev, 0, &err);

    FILE *f = fopen("kernels/qihse_core.cl", "r");
    fseek(f, 0, SEEK_END); size_t sz = ftell(f);
    char *src = malloc(sz + 1); rewind(f); fread(src, 1, sz, f); src[sz] = '\0'; fclose(f);
    cl_program prog = clCreateProgramWithSource(ctx, 1, (const char **)&src, NULL, &err);
    clBuildProgram(prog, 0, NULL, NULL, NULL, NULL);
    
    vec_k = clCreateKernel(prog, "qihse_vector_search", &err);
    mal_k = clCreateKernel(prog, "kp14_correlation_core", &err);
    intel_k = clCreateKernel(prog, "spectra_intel_core", &err);
    priv_k = clCreateKernel(prog, "priv_enforcer", &err);
    me_k = clCreateKernel(prog, "me_sentry_core", &err);
    
    dev_mal_sigs = clCreateBuffer(ctx, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, sizeof(mal_sigs), mal_sigs, NULL);
    dev_intel_keywords = clCreateBuffer(ctx, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, sizeof(intel_keywords), intel_keywords, NULL);
    
    free(src);
}

int handle_event(void *cb_ctx, void *data, size_t data_sz) {
    struct asic_event *e = data;
    
    if (e->type == EVENT_MALWARE) {
        cl_mem dev_payload = clCreateBuffer(ctx, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, MAX_PAYLOAD, e->payload, NULL);
        cl_mem dev_res = clCreateBuffer(ctx, CL_MEM_WRITE_ONLY, sizeof(int)*NUM_MALWARE_SIGS, NULL, NULL);
        int n_sigs = NUM_MALWARE_SIGS;
        clSetKernelArg(mal_k, 0, sizeof(cl_mem), &dev_payload);
        clSetKernelArg(mal_k, 1, sizeof(cl_mem), &dev_mal_sigs);
        clSetKernelArg(mal_k, 2, sizeof(cl_mem), &dev_res);
        clSetKernelArg(mal_k, 3, sizeof(int), &n_sigs);
        size_t gws = MAX_PAYLOAD / 8;
        clEnqueueNDRangeKernel(cmd_q, mal_k, 1, NULL, &gws, NULL, 0, NULL, NULL);
        int res[NUM_MALWARE_SIGS]; clEnqueueReadBuffer(cmd_q, dev_res, CL_TRUE, 0, sizeof(res), res, 0, NULL, NULL);
        for(int i=0; i<n_sigs; i++) if(res[i] > 0) printf("\033[1;31m[ASIC MALWARE ALERT] KP14 Signature Match: %X!\033[0m\n", (unsigned int)mal_sigs[i]);
        clReleaseMemObject(dev_payload); clReleaseMemObject(dev_res);
    }
    else if (e->type == EVENT_INTEL) {
        cl_mem dev_stream = clCreateBuffer(ctx, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, MAX_PAYLOAD, e->payload, NULL);
        cl_mem dev_res = clCreateBuffer(ctx, CL_MEM_WRITE_ONLY, sizeof(int)*INTEL_KEYWORD_COUNT, NULL, NULL);
        int k_len = INTEL_KEYWORD_LEN, k_cnt = INTEL_KEYWORD_COUNT;
        clSetKernelArg(intel_k, 0, sizeof(cl_mem), &dev_stream);
        clSetKernelArg(intel_k, 1, sizeof(cl_mem), &dev_intel_keywords);
        clSetKernelArg(intel_k, 2, sizeof(cl_mem), &dev_res);
        clSetKernelArg(intel_k, 3, sizeof(int), &k_len);
        clSetKernelArg(intel_k, 4, sizeof(int), &k_cnt);
        size_t gws = MAX_PAYLOAD;
        clEnqueueNDRangeKernel(cmd_q, intel_k, 1, NULL, &gws, NULL, 0, NULL, NULL);
        int res[INTEL_KEYWORD_COUNT]; clEnqueueReadBuffer(cmd_q, dev_res, CL_TRUE, 0, sizeof(res), res, 0, NULL, NULL);
        for(int i=0; i<k_cnt; i++) if(res[i] > 0) printf("\033[1;34m[ASIC INTEL ALERT] SPECTRA Keyword Match: %s!\033[0m\n", intel_keywords[i]);
        clReleaseMemObject(dev_stream); clReleaseMemObject(dev_res);
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) { printf("Usage: %s <ifname>\n", argv[0]); return 1; }
    signal(SIGINT, sig_handler);
    init_asic();
    struct bpf_object *obj = bpf_object__open_file("asic_sensor.bpf.o", NULL);
    bpf_object__load(obj);
    bpf_program__attach(bpf_object__find_program_by_name(obj, "trace_execve"));
    struct ring_buffer *rb = ring_buffer__new(bpf_object__find_map_fd_by_name(obj, "rb"), handle_event, NULL, NULL);
    printf("--- QIHSE MALWARE & INTEL ASIC ONLINE ---\n");
    while(!stop) ring_buffer__poll(rb, 100);
    ring_buffer__free(rb); bpf_object__close(obj);
    return 0;
}
