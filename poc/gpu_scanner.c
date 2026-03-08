
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <CL/cl.h>

#define DATA_SIZE (128 * 1024 * 1024) // 128 MB buffer for scanning
#define SIG_LEN 16
#define SIG_COUNT 4

const char *mal_signatures[SIG_COUNT] = {
    "/etc/shadow     ",
    "chmod +x        ",
    "curl -sL        ",
    "python -c       "
};

char *load_kernel_source(const char *filename) {
    FILE *fp = fopen(filename, "r");
    if (!fp) return NULL;
    fseek(fp, 0, SEEK_END);
    size_t size = ftell(fp);
    char *source = (char *)malloc(size + 1);
    rewind(fp);
    fread(source, 1, size, fp);
    source[size] = '\0';
    fclose(fp);
    return source;
}

int main() {
    cl_int err;
    cl_platform_id platform = NULL;
    cl_device_id device;
    cl_context context;
    cl_command_queue queue;
    cl_program program;
    cl_kernel kernel;

    // 1. Find NVIDIA Platform
    cl_platform_id platforms[4];
    cl_uint num_platforms;
    clGetPlatformIDs(4, platforms, &num_platforms);
    for(cl_uint i=0; i<num_platforms; i++) {
        char name[128];
        clGetPlatformInfo(platforms[i], CL_PLATFORM_NAME, 128, name, NULL);
        if(strstr(name, "NVIDIA")) { platform = platforms[i]; break; }
    }
    if (!platform) { printf("NVIDIA platform not found\n"); return 1; }

    clGetDeviceIDs(platform, CL_DEVICE_TYPE_GPU, 1, &device, NULL);
    context = clCreateContext(NULL, 1, &device, NULL, NULL, &err);
    queue = clCreateCommandQueue(context, device, 0, &err);

    // 2. Prepare Data
    char *host_data = (char *)malloc(DATA_SIZE);
    memset(host_data, 'A', DATA_SIZE);
    memcpy(&host_data[DATA_SIZE / 2], mal_signatures[0], SIG_LEN);
    memcpy(&host_data[DATA_SIZE / 4], mal_signatures[2], SIG_LEN);

    char *host_sigs = (char *)malloc(SIG_LEN * SIG_COUNT);
    for (int i = 0; i < SIG_COUNT; i++) memcpy(&host_sigs[i * SIG_LEN], mal_signatures[i], SIG_LEN);

    int *host_results = (int *)calloc(DATA_SIZE, sizeof(int));

    // 3. Setup Buffers
    cl_mem dev_data = clCreateBuffer(context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, DATA_SIZE, host_data, &err);
    cl_mem dev_sigs = clCreateBuffer(context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, SIG_LEN * SIG_COUNT, host_sigs, &err);
    cl_mem dev_results = clCreateBuffer(context, CL_MEM_WRITE_ONLY, DATA_SIZE * sizeof(int), NULL, &err);

    // 4. Build Program
    char *source = load_kernel_source("gpu_scanner.cl");
    program = clCreateProgramWithSource(context, 1, (const char **)&source, NULL, &err);
    clBuildProgram(program, 0, NULL, NULL, NULL, NULL);
    kernel = clCreateKernel(program, "signature_scanner", &err);

    // 5. Execute and Measure
    int d_len = DATA_SIZE;
    int s_len = SIG_LEN;
    int s_cnt = SIG_COUNT;
    clSetKernelArg(kernel, 0, sizeof(cl_mem), &dev_data);
    clSetKernelArg(kernel, 1, sizeof(cl_mem), &dev_sigs);
    clSetKernelArg(kernel, 2, sizeof(int), &d_len);
    clSetKernelArg(kernel, 3, sizeof(int), &s_len);
    clSetKernelArg(kernel, 4, sizeof(int), &s_cnt);
    clSetKernelArg(kernel, 5, sizeof(cl_mem), &dev_results);

    size_t global_work_size = DATA_SIZE;
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    
    clEnqueueNDRangeKernel(queue, kernel, 1, NULL, &global_work_size, NULL, 0, NULL, NULL);
    clFinish(queue);
    
    clock_gettime(CLOCK_MONOTONIC, &end);
    double elapsed = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;

    clEnqueueReadBuffer(queue, dev_results, CL_TRUE, 0, DATA_SIZE * sizeof(int), host_results, 0, NULL, NULL);

    // 6. Report Results
    printf("--- EDR Signature Scan Benchmark ---\n");
    printf("Buffer size: %d MB\n", DATA_SIZE / (1024 * 1024));
    printf("Signatures scanned: %d\n", SIG_COUNT);
    printf("Execution time: %.6f seconds\n", elapsed);
    printf("Throughput: %.2f GB/s\n", (double)DATA_SIZE / (1024.0 * 1024.0 * 1024.0) / elapsed);

    int matches = 0;
    for (int i = 0; i < DATA_SIZE; i++) {
        if (host_results[i] > 0) {
            printf("Found Malicious Signature ID %d at offset %d: %.16s\n", host_results[i], i, &host_data[i]);
            matches++;
        }
    }
    printf("Total matches: %d\n", matches);

    // Cleanup
    free(source); free(host_data); free(host_sigs); free(host_results);
    clReleaseMemObject(dev_data); clReleaseMemObject(dev_sigs); clReleaseMemObject(dev_results);
    clReleaseKernel(kernel); clReleaseProgram(program);
    clReleaseCommandQueue(queue); clReleaseContext(context);
    return 0;
}
