
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <CL/cl.h>
#include <bpf/libbpf.h>
#include "edr_common.h"

// OpenCL Global Setup
cl_context context;
cl_command_queue queue;
cl_kernel kernel;
cl_mem dev_sigs;
#define SIG_LEN 16
#define SIG_COUNT 4
const char *mal_signatures[SIG_COUNT] = { "/etc/shadow     ", "chmod +x        ", "curl -sL        ", "python -c       " };

static int stop = 0;
void sig_handler(int sig) { stop = 1; }

char *load_source(const char *fn) {
    FILE *fp = fopen(fn, "r");
    fseek(fp, 0, SEEK_END);
    size_t size = ftell(fp);
    char *src = (char *)malloc(size + 1);
    rewind(fp);
    fread(src, 1, size, fp);
    src[size] = '\0';
    fclose(fp);
    return src;
}

void init_gpu() {
    cl_platform_id platforms[4];
    cl_uint num_platforms;
    cl_platform_id platform = NULL;
    clGetPlatformIDs(4, platforms, &num_platforms);
    for(cl_uint i=0; i<num_platforms; i++) {
        char name[128];
        clGetPlatformInfo(platforms[i], CL_PLATFORM_NAME, 128, name, NULL);
        if(strstr(name, "NVIDIA")) { platform = platforms[i]; break; }
    }
    if (!platform) { printf("NVIDIA platform not found\n"); exit(1); }
    cl_device_id device;
    clGetDeviceIDs(platform, CL_DEVICE_TYPE_GPU, 1, &device, NULL);
    context = clCreateContext(NULL, 1, &device, NULL, NULL, NULL);
    queue = clCreateCommandQueue(context, device, 0, NULL);
    
    char *src = load_source("gpu_scanner.cl");
    cl_program program = clCreateProgramWithSource(context, 1, (const char **)&src, NULL, NULL);
    clBuildProgram(program, 0, NULL, NULL, NULL, NULL);
    kernel = clCreateKernel(program, "signature_scanner", NULL);
    
    char *sigs = (char *)malloc(SIG_LEN * SIG_COUNT);
    for (int i = 0; i < SIG_COUNT; i++) memcpy(&sigs[i * SIG_LEN], mal_signatures[i], SIG_LEN);
    dev_sigs = clCreateBuffer(context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, SIG_LEN * SIG_COUNT, sigs, NULL);
    free(sigs); free(src);
}

int handle_event(void *ctx, void *data, size_t data_sz) {
    struct event *e = data;
    printf("[SENSOR] Process %d (%s) ran: %s\n", e->pid, e->comm, e->cmdline);
    
    // Scan one event on the GPU (in a real system, we would batch thousands)
    cl_mem dev_data = clCreateBuffer(context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, MAX_CMDLINE_SIZE, e->cmdline, NULL);
    cl_mem dev_res = clCreateBuffer(context, CL_MEM_WRITE_ONLY, MAX_CMDLINE_SIZE * sizeof(int), NULL, NULL);
    
    int d_len = MAX_CMDLINE_SIZE;
    int s_len = SIG_LEN;
    int s_cnt = SIG_COUNT;
    clSetKernelArg(kernel, 0, sizeof(cl_mem), &dev_data);
    clSetKernelArg(kernel, 1, sizeof(cl_mem), &dev_sigs);
    clSetKernelArg(kernel, 2, sizeof(int), &d_len);
    clSetKernelArg(kernel, 3, sizeof(int), &s_len);
    clSetKernelArg(kernel, 4, sizeof(int), &s_cnt);
    clSetKernelArg(kernel, 5, sizeof(cl_mem), &dev_res);
    
    size_t gws = MAX_CMDLINE_SIZE;
    clEnqueueNDRangeKernel(queue, kernel, 1, NULL, &gws, NULL, 0, NULL, NULL);
    clFinish(queue);
    
    int results[MAX_CMDLINE_SIZE];
    clEnqueueReadBuffer(queue, dev_res, CL_TRUE, 0, MAX_CMDLINE_SIZE * sizeof(int), results, 0, NULL, NULL);
    
    for (int i = 0; i < MAX_CMDLINE_SIZE; i++) {
        if (results[i] > 0 && results[i] <= SIG_COUNT) {
            printf("\033[1;31m[GPU ALERT] Malicious signature ID %d found in command from PID %d!\033[0m\n", results[i], e->pid);
        }
    }
    
    clReleaseMemObject(dev_data);
    clReleaseMemObject(dev_res);
    return 0;
}

int main() {
    signal(SIGINT, sig_handler);
    init_gpu();
    printf("--- Hybrid EDR System Started (GPU Brain Initialized) ---\n");
    
    struct bpf_object *obj = bpf_object__open_file("edr_sensor.bpf.o", NULL);
    bpf_object__load(obj);
    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "trace_execve");
    bpf_program__attach(prog);
    
    int rb_fd = bpf_object__find_map_fd_by_name(obj, "rb");
    struct ring_buffer *rb = ring_buffer__new(rb_fd, handle_event, NULL, NULL);
    
    while (!stop) {
        ring_buffer__poll(rb, 100);
    }
    
    printf("Shutting down...\n");
    ring_buffer__free(rb);
    bpf_object__close(obj);
    return 0;
}
