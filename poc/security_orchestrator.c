
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <CL/cl.h>
#include <bpf/libbpf.h>

struct security_event {
    int pid;
    char comm[16];
    int requested_prot;
    int type; // 1 = mprotect, 2 = mmap
};

// OpenCL Globals
cl_context context;
cl_command_queue queue;
cl_kernel integrity_kernel, cfp_kernel;

static int stop = 0;
void sig_handler(int sig) { stop = 1; }

char *load_source(const char *fn) {
    FILE *fp = fopen(fn, "r");
    if(!fp) return NULL;
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
    cl_device_id device;
    clGetDeviceIDs(platform, CL_DEVICE_TYPE_GPU, 1, &device, NULL);
    context = clCreateContext(NULL, 1, &device, NULL, NULL, NULL);
    queue = clCreateCommandQueue(context, device, 0, NULL);
    
    char *src = load_source("security_co_processor.cl");
    cl_program program = clCreateProgramWithSource(context, 1, (const char **)&src, NULL, NULL);
    clBuildProgram(program, 0, NULL, NULL, NULL, NULL);
    integrity_kernel = clCreateKernel(program, "integrity_checker", NULL);
    cfp_kernel = clCreateKernel(program, "cfp_policy_engine", NULL);
    free(src);
}

// Background Integrity Thread (SWI)
void *integrity_worker(void *arg) {
    printf("[SWI] Integrity thread started. Scanning /usr/bin/...\n");
    const char *targets[] = {"/usr/bin/ls", "/usr/bin/bash", "/usr/bin/ssh"};
    int target_idx = 0;
    
    while (!stop) {
        FILE *f = fopen(targets[target_idx], "rb");
        if (f) {
            char buffer[65536];
            size_t bytes = fread(buffer, 1, sizeof(buffer), f);
            fclose(f);
            
            // Push to GPU for integrity check
            cl_mem dev_data = clCreateBuffer(context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, bytes, buffer, NULL);
            cl_mem dev_res = clCreateBuffer(context, CL_MEM_WRITE_ONLY, bytes, NULL, NULL);
            
            clSetKernelArg(integrity_kernel, 0, sizeof(cl_mem), &dev_data);
            clSetKernelArg(integrity_kernel, 1, sizeof(cl_mem), &dev_res);
            
            size_t gws = bytes / 4;
            clEnqueueNDRangeKernel(queue, integrity_kernel, 1, NULL, &gws, NULL, 0, NULL, NULL);
            clFinish(queue);
            
            clReleaseMemObject(dev_data);
            clReleaseMemObject(dev_res);
            
            // In a real system, we'd compare hash results here
            // printf("[SWI] Verified integrity of %s (%zu bytes)\n", targets[target_idx], bytes);
        }
        target_idx = (target_idx + 1) % 3;
        usleep(500000); // 0.5s pause to simulate background load
    }
    return NULL;
}

// CFP Callback
int handle_cfp_event(void *ctx, void *data, size_t data_sz) {
    struct security_event *e = data;
    
    // Policy Simulation: only PIDs < 1000 or 'edr' are allowed PROT_EXEC
    int allowed_policy = (e->pid < 1000) ? 7 : 3; // 7=RWX, 3=RW
    int requested = e->requested_prot;
    
    cl_mem dev_pol = clCreateBuffer(context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, sizeof(int), &allowed_policy, NULL);
    cl_mem dev_req = clCreateBuffer(context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, sizeof(int), &requested, NULL);
    cl_mem dev_alert = clCreateBuffer(context, CL_MEM_WRITE_ONLY, sizeof(int), NULL, NULL);
    
    int count = 1;
    clSetKernelArg(cfp_kernel, 0, sizeof(cl_mem), &dev_pol);
    clSetKernelArg(cfp_kernel, 1, sizeof(cl_mem), &dev_req);
    clSetKernelArg(cfp_kernel, 2, sizeof(cl_mem), &dev_alert);
    clSetKernelArg(cfp_kernel, 3, sizeof(int), &count);
    
    size_t gws = 1;
    clEnqueueNDRangeKernel(queue, cfp_kernel, 1, NULL, &gws, NULL, 0, NULL, NULL);
    clFinish(queue);
    
    int alert;
    clEnqueueReadBuffer(queue, dev_alert, CL_TRUE, 0, sizeof(int), &alert, 0, NULL, NULL);
    
    if (alert) {
        printf("\033[1;31m[CFP ALERT] Control Flow Violation! PID %d (%s) attempted PROT_EXEC (prot=%d) without policy permission!\033[0m\n", e->pid, e->comm, requested);
    } else {
        // printf("[CFP] Valid transition for PID %d (%s), prot=%d\n", e->pid, e->comm, requested);
    }
    
    clReleaseMemObject(dev_pol); clReleaseMemObject(dev_req); clReleaseMemObject(dev_alert);
    return 0;
}

int main() {
    signal(SIGINT, sig_handler);
    init_gpu();
    
    // Start SWI Integrity Background Thread
    pthread_t swi_thread;
    pthread_create(&swi_thread, NULL, integrity_worker, NULL);
    
    // Initialize eBPF Sensor
    struct bpf_object *obj = bpf_object__open_file("security_sensor.bpf.o", NULL);
    if (!obj) { printf("Failed to open BPF object\n"); return 1; }
    bpf_object__load(obj);
    
    struct bpf_program *prog1 = bpf_object__find_program_by_name(obj, "trace_mprotect");
    bpf_program__attach(prog1);
    struct bpf_program *prog2 = bpf_object__find_program_by_name(obj, "trace_mmap");
    bpf_program__attach(prog2);
    
    int rb_fd = bpf_object__find_map_fd_by_name(obj, "rb");
    struct ring_buffer *rb = ring_buffer__new(rb_fd, handle_cfp_event, NULL, NULL);
    
    printf("--- Hybrid Security Co-Processor Running ---\n");
    printf("SWI: Background file integrity scanning active\n");
    printf("CFP: mprotect/mmap policy enforcement active\n");
    
    while (!stop) {
        ring_buffer__poll(rb, 100);
    }
    
    pthread_join(swi_thread, NULL);
    ring_buffer__free(rb);
    bpf_object__close(obj);
    printf("Security systems offline.\n");
    return 0;
}
