
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
#include <fcntl.h>
#include "asic_common.h"

// ASIC Configuration
#define DB_SIZE 800
#define VECTOR_DIMS 160
#define NUM_MALWARE_SIGS 10
#define INTEL_KEYWORD_LEN 16
#define INTEL_KEYWORD_COUNT 4
#define MAX_CODE_SNIPPETS 5000
#define NUM_MASKS 4
#define PMC_WINDOW 10

// OpenCL Globals
cl_context ctx;
cl_command_queue cmd_q;
cl_kernel vec_k, super_k, entropy_k, priv_k, me_k, rf_k, mal_k, intel_k, code_k, evolution_k, me_crypto_k;
cl_mem db_vectors_mem, dev_masks, dev_mal_sigs, dev_intel_keywords, dev_codebase;

unsigned long threat_masks[NUM_MASKS] = { 0x2f6574632f736861, 0x63686d6f64202b78, 0x6375726c202d734c, 0x707974686f6e202d };
unsigned long mal_sigs[NUM_MALWARE_SIGS] = { 0xDEADC0DE, 0xBEEFBABE, 0x1337C0DE };
const char intel_keywords[INTEL_KEYWORD_COUNT][INTEL_KEYWORD_LEN] = { "0day            ", "exploit         ", "cve-2026        ", "payload         " };

static int stop = 0;
void sig_handler(int sig) { stop = 1; }

extern void* perform_compliance_check(void* arg);

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
    code_k = clCreateKernel(prog, "code_intelligence_core", &err);
    priv_k = clCreateKernel(prog, "priv_enforcer", &err);
    me_k = clCreateKernel(prog, "me_sentry_core", &err);
    evolution_k = clCreateKernel(prog, "qihse_hebbian_update", &err);
    me_crypto_k = clCreateKernel(prog, "me_cryptanalysis_core", &err);
    entropy_k = clCreateKernel(prog, "qihse_entropy_analyzer", &err);
    
    dev_mal_sigs = clCreateBuffer(ctx, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, sizeof(mal_sigs), mal_sigs, NULL);
    dev_intel_keywords = clCreateBuffer(ctx, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, sizeof(intel_keywords), intel_keywords, NULL);
    dev_codebase = clCreateBuffer(ctx, CL_MEM_READ_WRITE, MAX_CODE_SNIPPETS * 160 * sizeof(float), NULL, NULL);
    dev_masks = clCreateBuffer(ctx, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, sizeof(threat_masks), threat_masks, NULL);
    
    float *h_db = (float *)malloc(DB_SIZE * VECTOR_DIMS * sizeof(float));
    FILE *db_f = fopen("threat_tensors.bin", "rb");
    if(db_f) { fread(h_db, sizeof(float), DB_SIZE * VECTOR_DIMS, db_f); fclose(db_f); }
    db_vectors_mem = clCreateBuffer(ctx, CL_MEM_READ_WRITE | CL_MEM_COPY_HOST_PTR, DB_SIZE * VECTOR_DIMS * sizeof(float), h_db, NULL);
    free(src); free(h_db);
}

// L3 Pipeline: Hardware Telemetry -> Entropy & Crypto Cores
void *l3_hardware_thread(void *arg) {
    FILE *pipe = popen("./pmc_sensor", "r");
    if(!pipe) return NULL;
    char line[128]; float pmc_window[PMC_WINDOW]; int count = 0;
    while(!stop && fgets(line, sizeof(line), pipe)) {
        if(strncmp(line, "PMC_DATA:", 9) == 0) {
            pmc_window[count++] = atof(line + 9);
            if(count == PMC_WINDOW) {
                cl_mem dev_pmc = clCreateBuffer(ctx, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, sizeof(pmc_window), pmc_window, NULL);
                cl_mem dev_anom = clCreateBuffer(ctx, CL_MEM_WRITE_ONLY, sizeof(float), NULL, NULL);
                int win = PMC_WINDOW;
                clSetKernelArg(entropy_k, 0, sizeof(cl_mem), &dev_pmc);
                clSetKernelArg(entropy_k, 1, sizeof(cl_mem), &dev_anom);
                clSetKernelArg(entropy_k, 2, sizeof(int), &win);
                size_t gws = 1; clEnqueueNDRangeKernel(cmd_q, entropy_k, 1, NULL, &gws, NULL, 0, NULL, NULL);
                float anom_score; clEnqueueReadBuffer(cmd_q, dev_anom, CL_TRUE, 0, sizeof(float), &anom_score, 0, NULL, NULL);
                if(anom_score > 1000000.0f) printf("\033[1;33m[ASIC L3 ALERT] Hardware Cache-Timing Anomaly!\033[0m\n");
                
                int num_hyp = 256;
                cl_mem dev_cr = clCreateBuffer(ctx, CL_MEM_WRITE_ONLY, sizeof(float) * num_hyp, NULL, NULL);
                clSetKernelArg(me_crypto_k, 0, sizeof(cl_mem), &dev_pmc);
                clSetKernelArg(me_crypto_k, 1, sizeof(cl_mem), &dev_cr);
                clSetKernelArg(me_crypto_k, 2, sizeof(int), &win);
                clSetKernelArg(me_crypto_k, 3, sizeof(int), &num_hyp);
                size_t cgws = num_hyp; clEnqueueNDRangeKernel(cmd_q, me_crypto_k, 1, NULL, &cgws, NULL, 0, NULL, NULL);
                float csc[256]; clEnqueueReadBuffer(cmd_q, dev_cr, CL_TRUE, 0, sizeof(csc), csc, 0, NULL, NULL);
                
                float mc = 0.0f; int bg = 0;
                for(int i=0; i<num_hyp; i++) { if (csc[i] > mc) { mc = csc[i]; bg = i; } }
                if (mc > 0.85f) printf("\033[1;36m[ASIC L6 CRYPTO] ME Key Byte %02X extracted! (Confidence: %.2f)\033[0m\n", bg, mc);

                clReleaseMemObject(dev_pmc); clReleaseMemObject(dev_anom); clReleaseMemObject(dev_cr);
                count = 0;
            }
        }
    }
    pclose(pipe); return NULL;
}

// ME Activator: Occasionally triggers ME to generate traces
void *me_activator_thread(void *arg) {
    while (!stop) {
        int fd = open("/dev/mei0", O_RDWR);
        if (fd >= 0) {
            // Send a safe "Get Version" or status ping to HECI
            unsigned char ping[] = {0x01, 0x00, 0x00, 0x00};
            write(fd, ping, sizeof(ping));
            close(fd);
            // printf("[ASIC L6] ME Side-Channel Triggered.\n");
        }
        sleep(30); // Trigger every 30 seconds
    }
    return NULL;
}

int handle_event(void *cb_ctx, void *data, size_t data_sz) {
    struct asic_event *e = data;
    if (e->type == EVENT_NET || e->type == EVENT_EXEC) {
        if (e->type == EVENT_NET) {
            printf("[TRAFFIC] L1_EDGE | %02X %02X %02X %02X %02X %02X %02X %02X...\n", 
                   (unsigned char)e->payload[0], (unsigned char)e->payload[1], (unsigned char)e->payload[2], (unsigned char)e->payload[3],
                   (unsigned char)e->payload[4], (unsigned char)e->payload[5], (unsigned char)e->payload[6], (unsigned char)e->payload[7]);
        } else {
            printf("[TRAFFIC] L2_EXEC | %s\n", e->comm);
            float q[VECTOR_DIMS] = {0.0f};
            for(int i=0; i<16 && i<VECTOR_DIMS; i++) q[i] = (float)(e->payload[i]) / 255.0f;
            cl_mem dq = clCreateBuffer(ctx, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, sizeof(q), q, NULL);
            cl_mem ds = clCreateBuffer(ctx, CL_MEM_WRITE_ONLY, sizeof(float)*DB_SIZE, NULL, NULL);
            int ndb = DB_SIZE;
            clSetKernelArg(vec_k, 0, sizeof(cl_mem), &db_vectors_mem);
            clSetKernelArg(vec_k, 1, sizeof(cl_mem), &dq);
            clSetKernelArg(vec_k, 2, sizeof(cl_mem), &ds);
            clSetKernelArg(vec_k, 3, sizeof(int), &ndb);
            size_t gws = DB_SIZE; clEnqueueNDRangeKernel(cmd_q, vec_k, 1, NULL, &gws, NULL, 0, NULL, NULL);
            float sc[DB_SIZE]; clEnqueueReadBuffer(cmd_q, ds, CL_TRUE, 0, sizeof(sc), sc, 0, NULL, NULL);
            float ms = 0.0f; int bt = 0;
            for(int i=0; i<DB_SIZE; i++) { if(sc[i] > ms) { ms = sc[i]; bt = i; } }
            if(ms > 0.92f) printf("\033[1;35m[ASIC VECTOR ALERT] APT %d Behavior Detected! Score: %.2f\033[0m\n", bt/100, ms);
            else if (ms > 0.60f && ms < 0.92f) {
                float lr = 0.05f;
                clSetKernelArg(evolution_k, 0, sizeof(cl_mem), &db_vectors_mem);
                clSetKernelArg(evolution_k, 1, sizeof(cl_mem), &dq);
                clSetKernelArg(evolution_k, 2, sizeof(int), &bt);
                clSetKernelArg(evolution_k, 3, sizeof(float), &lr);
                size_t egws = VECTOR_DIMS; clEnqueueNDRangeKernel(cmd_q, evolution_k, 1, NULL, &egws, NULL, 0, NULL, NULL);
                printf("[ASIC EVOLVE] Polymorphic drift adapted. Tensor DB optimized (Vector %d).\n", bt);
            }
            clReleaseMemObject(dq); clReleaseMemObject(ds);
        }
        cl_mem dp = clCreateBuffer(ctx, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, MAX_PAYLOAD, e->payload, NULL);
        cl_mem dr = clCreateBuffer(ctx, CL_MEM_WRITE_ONLY, sizeof(int)*NUM_MASKS, NULL, NULL);
        int blk = MAX_PAYLOAD / 8, nmk = NUM_MASKS;
        clSetKernelArg(super_k, 0, sizeof(cl_mem), &dp);
        clSetKernelArg(super_k, 1, sizeof(cl_mem), &dev_masks);
        clSetKernelArg(super_k, 2, sizeof(cl_mem), &dr);
        clSetKernelArg(super_k, 3, sizeof(int), &blk);
        clSetKernelArg(super_k, 4, sizeof(int), &nmk);
        size_t gws = blk; clEnqueueNDRangeKernel(cmd_q, super_k, 1, NULL, &gws, NULL, 0, NULL, NULL);
        int res[NUM_MASKS]; clEnqueueReadBuffer(cmd_q, dr, CL_TRUE, 0, sizeof(res), res, 0, NULL, NULL);
        for(int i=0; i<nmk; i++) if(res[i] > 0) printf("\033[1;31m[ASIC ALERT] Signature Match %d (PID %d)!\033[0m\n", i, e->pid);
        clReleaseMemObject(dp); clReleaseMemObject(dr);
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) { printf("Usage: %s <ifname1> [ifname2] ...\n", argv[0]); return 1; }
    signal(SIGINT, sig_handler);
    init_asic();
    pthread_t comp_t, l3_t, mea_t;
    pthread_create(&comp_t, NULL, perform_compliance_check, NULL);
    pthread_create(&l3_t, NULL, l3_hardware_thread, NULL);
    pthread_create(&mea_t, NULL, me_activator_thread, NULL);
    
    struct bpf_object *obj = bpf_object__open_file("asic_sensor.bpf.o", NULL);
    if (!obj || bpf_object__load(obj)) { printf("BPF Load Fail\n"); return 1; }
    bpf_program__attach(bpf_object__find_program_by_name(obj, "trace_execve"));
    struct bpf_program *xdp_p = bpf_object__find_program_by_name(obj, "xdp_me_monitor");
    for (int i = 1; i < argc; i++) {
        int ifidx = if_nametoindex(argv[i]);
        if (ifidx > 0) bpf_xdp_attach(ifidx, bpf_program__fd(xdp_p), XDP_FLAGS_SKB_MODE, NULL);
    }
    struct ring_buffer *rb = ring_buffer__new(bpf_object__find_map_fd_by_name(obj, "rb"), handle_event, NULL, NULL);
    printf("--- ASI COMMAND CENTER BACKEND ONLINE ---\n");
    while(!stop) if (rb) ring_buffer__poll(rb, 100);
    ring_buffer__free(rb); bpf_object__close(obj);
    return 0;
}
