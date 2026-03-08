
#include <math.h>
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
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include "asic_common.h"

// ASIC Overdrive Config
#define MAX_DB_SIZE 100000 
#define VECTOR_DIMS 160
#define NUM_MALWARE_SIGS 10
#define INTEL_KEYWORD_LEN 16
#define INTEL_KEYWORD_COUNT 4
#define MAX_CODE_SNIPPETS 5000
#define NUM_MASKS 4
#define PMC_WINDOW 100
#define NUM_HYPOTHESES (256 * 1024)
#define BLACKBOX_SIZE (10 * 1024 * 1024)

// OpenCL Globals
cl_context ctx;
cl_command_queue cmd_q;
cl_kernel vec_k, super_k, entropy_k, priv_k, me_k, rf_k, mal_k, intel_k, code_k, evolution_k, me_berserker_k, me_finalizer_k, hammer_k, blackbox_k;
cl_mem db_vectors_mem, dev_masks, dev_mal_sigs, dev_intel_keywords, dev_codebase, blackbox_mem;
cl_mem dev_sum_x, dev_sum_xy, dev_sum_x2;

static int actual_db_size = 0;

// Swarm Intelligence Globals
int swarm_sd;
struct sockaddr_in swarm_addr;

// Vault State
static int vault_locked = 0;

unsigned long threat_masks[NUM_MASKS] = { 0x2f6574632f736861, 0x63686d6f64202b78, 0x6375726c202d734c, 0x707974686f6e202d };
unsigned long mal_sigs[NUM_MALWARE_SIGS] = { 0xDEADC0DE, 0xBEEFBABE, 0x1337C0DE };
const char intel_keywords[INTEL_KEYWORD_COUNT][INTEL_KEYWORD_LEN] = { "0day            ", "exploit         ", "cve-2026        ", "payload         " };

static float total_traces_processed = 0.0f;
static int stop = 0;
static int hammer_mode = 0;
static int blackbox_offset = 0;

void sig_handler(int sig) { 
    if (sig == SIGINT) stop = 1; 
    else if (sig == SIGUSR1) {
        hammer_mode = !hammer_mode;
        if (hammer_mode) printf("[HAMMER: ON]\n");
        else printf("[HAMMER: OFF]\n");
        fflush(stdout);
    } else if (sig == SIGUSR2) {
        vault_locked = !vault_locked;
        if (vault_locked) printf("[VAULT] LOCKED\n");
        else printf("[VAULT] UNLOCKED\n");
        fflush(stdout);
    }
}

void *swarm_listener(void *arg) {
    int sd = socket(AF_INET, SOCK_DGRAM, 0);
    int reuse = 1;
    setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(5000);
    bind(sd, (struct sockaddr *)&addr, sizeof(addr));
    struct ip_mreq mreq;
    mreq.imr_multiaddr.s_addr = inet_addr("239.0.0.1");
    mreq.imr_interface.s_addr = htonl(INADDR_ANY);
    setsockopt(sd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq));
    char buf[1024];
    while (!stop) {
        int n = recv(sd, buf, sizeof(buf), 0);
        if (n > 0) { printf("[SWARM] Received Vector Drift from Peer\n"); fflush(stdout); }
    }
    close(sd);
    return NULL;
}

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
    me_berserker_k = clCreateKernel(prog, "me_berserker_core", &err);
    me_finalizer_k = clCreateKernel(prog, "me_correlation_finalizer", &err);
    entropy_k = clCreateKernel(prog, "qihse_entropy_analyzer", &err);
    super_k = clCreateKernel(prog, "qihse_superposition_match", &err);
    hammer_k = clCreateKernel(prog, "me_hammer_core", &err);
    blackbox_k = clCreateKernel(prog, "blackbox_append", &err);
    
    dev_mal_sigs = clCreateBuffer(ctx, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, sizeof(mal_sigs), mal_sigs, NULL);
    dev_intel_keywords = clCreateBuffer(ctx, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, sizeof(intel_keywords), intel_keywords, NULL);
    dev_codebase = clCreateBuffer(ctx, CL_MEM_READ_WRITE, MAX_CODE_SNIPPETS * 160 * sizeof(float), NULL, NULL);
    dev_masks = clCreateBuffer(ctx, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, sizeof(threat_masks), threat_masks, NULL);
    blackbox_mem = clCreateBuffer(ctx, CL_MEM_READ_WRITE, BLACKBOX_SIZE, NULL, NULL);
    
    dev_sum_x = clCreateBuffer(ctx, CL_MEM_READ_WRITE, sizeof(float) * NUM_HYPOTHESES, NULL, NULL);
    dev_sum_xy = clCreateBuffer(ctx, CL_MEM_READ_WRITE, sizeof(float) * NUM_HYPOTHESES, NULL, NULL);
    dev_sum_x2 = clCreateBuffer(ctx, CL_MEM_READ_WRITE, sizeof(float) * NUM_HYPOTHESES, NULL, NULL);

    swarm_sd = socket(AF_INET, SOCK_DGRAM, 0);
    memset(&swarm_addr, 0, sizeof(swarm_addr));
    swarm_addr.sin_family = AF_INET;
    swarm_addr.sin_addr.s_addr = inet_addr("239.0.0.1");
    swarm_addr.sin_port = htons(5000);
    
    FILE *db_f = fopen("threat_tensors.bin", "rb");
    if(db_f) { 
        fseek(db_f, 0, SEEK_END);
        long f_size = ftell(db_f);
        rewind(db_f);
        actual_db_size = f_size / (VECTOR_DIMS * sizeof(float));
        if (actual_db_size > MAX_DB_SIZE) actual_db_size = MAX_DB_SIZE;
        printf("[ASIC] Loaded %d Threat Tensors from DB.\n", actual_db_size);
        fflush(stdout);

        float *h_db = (float *)malloc(actual_db_size * VECTOR_DIMS * sizeof(float));
        fread(h_db, sizeof(float), actual_db_size * VECTOR_DIMS, db_f); 
        fclose(db_f); 
        db_vectors_mem = clCreateBuffer(ctx, CL_MEM_READ_WRITE | CL_MEM_COPY_HOST_PTR, actual_db_size * VECTOR_DIMS * sizeof(float), h_db, NULL);
        free(h_db);
    } else {
        printf("[ASIC] WARNING: No Threat DB found! Creating empty buffer.\n");
        actual_db_size = 0;
        db_vectors_mem = clCreateBuffer(ctx, CL_MEM_READ_WRITE, 1 * VECTOR_DIMS * sizeof(float), NULL, NULL);
    }
    
    float *zeros = calloc(NUM_HYPOTHESES, sizeof(float));
    clEnqueueWriteBuffer(cmd_q, dev_sum_x, CL_TRUE, 0, sizeof(float)*NUM_HYPOTHESES, zeros, 0, NULL, NULL);
    clEnqueueWriteBuffer(cmd_q, dev_sum_xy, CL_TRUE, 0, sizeof(float)*NUM_HYPOTHESES, zeros, 0, NULL, NULL);
    clEnqueueWriteBuffer(cmd_q, dev_sum_x2, CL_TRUE, 0, sizeof(float)*NUM_HYPOTHESES, zeros, 0, NULL, NULL);
    
    free(zeros); free(src);
}

void *l3_hardware_thread(void *arg) {
    FILE *pipe = popen("./pmc_sensor", "r");
    if(!pipe) return NULL;
    char line[128]; float pmc_window[PMC_WINDOW]; int count = 0;
    while(!stop && fgets(line, sizeof(line), pipe)) {
        if(strncmp(line, "PMC_DATA:", 9) == 0) {
            pmc_window[count++] = atof(line + 9);
            if(count == PMC_WINDOW) {
                total_traces_processed += 1.0f;
                cl_mem dev_pmc = clCreateBuffer(ctx, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, sizeof(pmc_window), pmc_window, NULL);
                int tw = PMC_WINDOW, nh = NUM_HYPOTHESES;
                
                if (hammer_mode) {
                    // Hammer Mode: Use float4 vectorized kernel with 8x iterations per trace for 100% spike
                    int v_nh = NUM_HYPOTHESES / 4;
                    int v_tw = PMC_WINDOW / 4;
                    clSetKernelArg(hammer_k, 0, sizeof(cl_mem), &dev_pmc);
                    clSetKernelArg(hammer_k, 1, sizeof(cl_mem), &dev_sum_x);
                    clSetKernelArg(hammer_k, 2, sizeof(cl_mem), &dev_sum_xy);
                    clSetKernelArg(hammer_k, 3, sizeof(cl_mem), &dev_sum_x2);
                    clSetKernelArg(hammer_k, 4, sizeof(int), &v_tw);
                    clSetKernelArg(hammer_k, 5, sizeof(int), &v_nh);
                    size_t gws = v_nh;
                    for(int i=0; i<8; i++) {
                        clEnqueueNDRangeKernel(cmd_q, hammer_k, 1, NULL, &gws, NULL, 0, NULL, NULL);
                    }
                    clFinish(cmd_q);
                } else {
                    clSetKernelArg(me_berserker_k, 0, sizeof(cl_mem), &dev_pmc);
                    clSetKernelArg(me_berserker_k, 1, sizeof(cl_mem), &dev_sum_x);
                    clSetKernelArg(me_berserker_k, 2, sizeof(cl_mem), &dev_sum_xy);
                    clSetKernelArg(me_berserker_k, 3, sizeof(cl_mem), &dev_sum_x2);
                    clSetKernelArg(me_berserker_k, 4, sizeof(int), &tw);
                    clSetKernelArg(me_berserker_k, 5, sizeof(int), &nh);
                    size_t gws = NUM_HYPOTHESES;
                    clEnqueueNDRangeKernel(cmd_q, me_berserker_k, 1, NULL, &gws, NULL, 0, NULL, NULL);
                }
                
                if ((int)total_traces_processed % 50 == 0) {
                    cl_mem dev_res = clCreateBuffer(ctx, CL_MEM_WRITE_ONLY, sizeof(float)*NUM_HYPOTHESES, NULL, NULL);
                    clSetKernelArg(me_finalizer_k, 0, sizeof(cl_mem), &dev_sum_x);
                    clSetKernelArg(me_finalizer_k, 1, sizeof(cl_mem), &dev_sum_xy);
                    clSetKernelArg(me_finalizer_k, 2, sizeof(cl_mem), &dev_sum_x2);
                    clSetKernelArg(me_finalizer_k, 3, sizeof(cl_mem), &dev_res);
                    clSetKernelArg(me_finalizer_k, 4, sizeof(float), &total_traces_processed);
                    clSetKernelArg(me_finalizer_k, 5, sizeof(int), &nh);
                    size_t gws = NUM_HYPOTHESES;
                    clEnqueueNDRangeKernel(cmd_q, me_finalizer_k, 1, NULL, &gws, NULL, 0, NULL, NULL);
                    float *scores = malloc(sizeof(float)*NUM_HYPOTHESES);
                    clEnqueueReadBuffer(cmd_q, dev_res, CL_TRUE, 0, sizeof(float)*NUM_HYPOTHESES, scores, 0, NULL, NULL);
                    float max_c = 0; int best = 0;
                    for(int i=0; i<nh; i++) { if(scores[i]>max_c) { max_c=scores[i]; best=i; } }
                    printf("\033[1;36m[ASIC L6 CRYPTO] Progress: %.0f traces | Best Match: %05X (Corr: %.4f) [HAMMER: %s]\033[0m\n", 
                           total_traces_processed, best, max_c, hammer_mode ? "ON" : "OFF");
                    printf("[CRYPTO_STATS] %f|%f\n", total_traces_processed, max_c);
                    fflush(stdout);
                    free(scores); clReleaseMemObject(dev_res);
                }
                clReleaseMemObject(dev_pmc);
                count = 0;
            }
        }
    }
    pclose(pipe); return NULL;
}

void *me_activator_thread(void *arg) {
    unsigned char payloads[4][4] = {
        {0x01, 0x00, 0x00, 0x00}, // Standard Ping
        {0x02, 0x05, 0x01, 0x00}, // Get Version
        {0x03, 0x01, 0x00, 0x02}, // Power State
        {0x08, 0xFF, 0xEE, 0xDD}  // Extended Telemetry
    };
    int p_idx = 0;

    while (!stop) {
        int fd = open("/dev/mei0", O_RDWR);
        if (fd >= 0) {
            if (hammer_mode) {
                // Vary payload to create diverse power signatures
                write(fd, payloads[p_idx], 4);
                p_idx = (p_idx + 1) % 4;
            } else {
                write(fd, payloads[0], 4);
            }
            close(fd);
        }
        // Hammer Mode runs at 10x frequency (50ms vs 500ms)
        usleep(hammer_mode ? 50000 : 500000); 
    }
    return NULL;
}

int handle_event(void *cb_ctx, void *data, size_t data_sz) {
    struct asic_event *e = data;
    if (e->type == EVENT_NET) {
        printf("[TRAFFIC] L1_EDGE | %02X %02X %02X %02X %02X...\n", (unsigned char)e->payload[0], (unsigned char)e->payload[1], (unsigned char)e->payload[2], (unsigned char)e->payload[3], (unsigned char)e->payload[4]);
    } else if (e->type == EVENT_EXEC) {
        printf("[TRAFFIC] L2_EDR  | %s -> %s\n", e->comm, e->payload);
    } else if (e->type == EVENT_ME) {
        printf("[TRAFFIC] L3_ME   | HECI MSG: %02X %02X %02X %02X\n", (unsigned char)e->payload[0], (unsigned char)e->payload[1], (unsigned char)e->payload[2], (unsigned char)e->payload[3]);
    }
    fflush(stdout);

    if (e->type == EVENT_NET || e->type == EVENT_EXEC) {
        if (e->type == EVENT_EXEC) {
            float q[VECTOR_DIMS] = {0.0f};
            for(int i=0; i<MAX_PAYLOAD && i < 160; i++) {
                unsigned char b = (unsigned char)e->payload[i];
                if(b == 0) break;
                q[b % VECTOR_DIMS] += 1.0f;
            }
            float q_norm = 0.0f;
            for(int i=0; i<VECTOR_DIMS; i++) q_norm += q[i]*q[i];
            if(q_norm > 0) {
                q_norm = sqrt(q_norm);
                for(int i=0; i<VECTOR_DIMS; i++) q[i] /= q_norm;
            }
            cl_mem dq = clCreateBuffer(ctx, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, sizeof(q), q, NULL);
            cl_mem ds = clCreateBuffer(ctx, CL_MEM_WRITE_ONLY, sizeof(float)*actual_db_size, NULL, NULL);
            int ndb = actual_db_size;
            clSetKernelArg(vec_k, 0, sizeof(cl_mem), &db_vectors_mem);
            clSetKernelArg(vec_k, 1, sizeof(cl_mem), &dq);
            clSetKernelArg(vec_k, 2, sizeof(cl_mem), &ds);
            clSetKernelArg(vec_k, 3, sizeof(int), &ndb);
            size_t gws = actual_db_size; clEnqueueNDRangeKernel(cmd_q, vec_k, 1, NULL, &gws, NULL, 0, NULL, NULL);
            float *sc = malloc(sizeof(float) * actual_db_size);
            clEnqueueReadBuffer(cmd_q, ds, CL_TRUE, 0, sizeof(float) * actual_db_size, sc, 0, NULL, NULL);
            float ms = 0.0f; int bt = 0;
            for(int i=0; i<actual_db_size; i++) { if(sc[i] > ms) { ms = sc[i]; bt = i; } }
            if(ms > 0.92f) {
                int apt_id = bt / 2000;
                if (apt_id == 8) printf("\033[1;31;5m[ASIC ALERT] CRITICAL: VAULT 7 / MARBLE MATCH! (%.2f)\033[0m\n", ms);
                else if (apt_id == 9) printf("\033[1;31;5m[ASIC ALERT] CRITICAL: FIRMWARE IMPLANT DETECTED! (%.2f)\033[0m\n", ms);
                else printf("\033[1;35m[ASIC VECTOR ALERT] APT %d Match! (%.2f)\033[0m\n", apt_id, ms);
                printf("[IPS] Terminated Process %d\n", e->pid);
                kill(e->pid, SIGKILL);
            } else if (ms > 0.60f) {
                float lr = 0.05f;
                clSetKernelArg(evolution_k, 0, sizeof(cl_mem), &db_vectors_mem);
                clSetKernelArg(evolution_k, 1, sizeof(cl_mem), &dq);
                clSetKernelArg(evolution_k, 2, sizeof(int), &bt);
                clSetKernelArg(evolution_k, 3, sizeof(float), &lr);
                size_t egws = VECTOR_DIMS; clEnqueueNDRangeKernel(cmd_q, evolution_k, 1, NULL, &egws, NULL, 0, NULL, NULL);
                printf("[ASIC EVOLVE] Tensor DB optimized (Vector %d).\n", bt);
                char msg[] = "EVOLUTION";
                sendto(swarm_sd, msg, sizeof(msg), 0, (struct sockaddr *)&swarm_addr, sizeof(swarm_addr));
            }
            free(sc); clReleaseMemObject(dq); clReleaseMemObject(ds);
        }
        cl_mem dp = clCreateBuffer(ctx, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, MAX_PAYLOAD, e->payload, NULL);
        
        if (blackbox_offset + 256 <= BLACKBOX_SIZE) {
            clSetKernelArg(blackbox_k, 0, sizeof(cl_mem), &blackbox_mem);
            clSetKernelArg(blackbox_k, 1, sizeof(cl_mem), &dp);
            clSetKernelArg(blackbox_k, 2, sizeof(int), &blackbox_offset);
            size_t bb_gws = 256;
            clEnqueueNDRangeKernel(cmd_q, blackbox_k, 1, NULL, &bb_gws, NULL, 0, NULL, NULL);
            blackbox_offset += 256;
        }

        cl_mem dr = clCreateBuffer(ctx, CL_MEM_WRITE_ONLY, sizeof(int)*NUM_MASKS, NULL, NULL);
        int blk = MAX_PAYLOAD / 8, nmk = NUM_MASKS;
        clSetKernelArg(super_k, 0, sizeof(cl_mem), &dp);
        clSetKernelArg(super_k, 1, sizeof(cl_mem), &dev_masks);
        clSetKernelArg(super_k, 2, sizeof(cl_mem), &dr);
        clSetKernelArg(super_k, 3, sizeof(int), &blk);
        clSetKernelArg(super_k, 4, sizeof(int), &nmk);
        size_t gws = blk; clEnqueueNDRangeKernel(cmd_q, super_k, 1, NULL, &gws, NULL, 0, NULL, NULL);
        int res[NUM_MASKS]; clEnqueueReadBuffer(cmd_q, dr, CL_TRUE, 0, sizeof(res), res, 0, NULL, NULL);
        for(int i=0; i<nmk; i++) if(res[i] > 0) printf("\033[1;31m[ASIC ALERT] Signature Match %d!\033[0m\n", i);
        clReleaseMemObject(dp); clReleaseMemObject(dr);
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) { printf("Usage: %s <ifname1> [ifname2] ...\n", argv[0]); return 1; }
    signal(SIGINT, sig_handler);
    signal(SIGUSR1, sig_handler);
    signal(SIGUSR2, sig_handler);
    init_asic();
    pthread_t comp_t, l3_t, mea_t, swarm_t;
    pthread_create(&comp_t, NULL, perform_compliance_check, NULL);
    pthread_create(&l3_t, NULL, l3_hardware_thread, NULL);
    pthread_create(&mea_t, NULL, me_activator_thread, NULL);
    pthread_create(&swarm_t, NULL, swarm_listener, NULL);
    struct bpf_object *obj = bpf_object__open_file("asic_sensor.bpf.o", NULL);
    if (!obj || bpf_object__load(obj)) { printf("BPF Load Fail\n"); return 1; }
    bpf_program__attach(bpf_object__find_program_by_name(obj, "trace_execve"));
    bpf_program__attach(bpf_object__find_program_by_name(obj, "trace_mei_write"));
    struct bpf_program *xdp_p = bpf_object__find_program_by_name(obj, "xdp_me_monitor");
    for (int i = 1; i < argc; i++) {
        int ifidx = if_nametoindex(argv[i]);
        if (ifidx > 0) bpf_xdp_attach(ifidx, bpf_program__fd(xdp_p), XDP_FLAGS_SKB_MODE, NULL);
    }
    struct ring_buffer *rb = ring_buffer__new(bpf_object__find_map_fd_by_name(obj, "rb"), handle_event, NULL, NULL);
    printf("--- ASI COMMAND CENTER BACKEND ONLINE ---\n");
    while(!stop) if (rb) ring_buffer__poll(rb, 100);
    
    printf("\n[ASIC] Shutting down. Dumping Blackbox...\n");
    char *bb_buf = malloc(BLACKBOX_SIZE);
    if (bb_buf) {
        clEnqueueReadBuffer(cmd_q, blackbox_mem, CL_TRUE, 0, BLACKBOX_SIZE, bb_buf, 0, NULL, NULL);
        FILE *bb_f = fopen("blackbox.bin", "wb");
        if (bb_f) {
            fwrite(bb_buf, 1, blackbox_offset, bb_f);
            fclose(bb_f);
            printf("[ASIC] Blackbox dumped to blackbox.bin (%d bytes)\n", blackbox_offset);
        }
        free(bb_buf);
    }

    ring_buffer__free(rb); bpf_object__close(obj);
    return 0;
}
