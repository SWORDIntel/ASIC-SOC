
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <linux/perf_event.h>
#include <asm/unistd.h>
#include <sys/ioctl.h>
#include <stdint.h>

long perf_event_open(struct perf_event_attr *hw_event, pid_t pid, int cpu, int group_fd, unsigned long flags) {
    return syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
}

int main() {
    struct perf_event_attr pe;
    memset(&pe, 0, sizeof(pe));
    pe.type = PERF_TYPE_HARDWARE;
    pe.size = sizeof(pe);
    pe.config = PERF_COUNT_HW_CACHE_MISSES;
    pe.disabled = 1;
    pe.exclude_kernel = 1;
    pe.exclude_hv = 1;

    int fd = perf_event_open(&pe, 0, -1, -1, 0); // Monitor all CPUs for current process
    if (fd == -1) {
        perror("perf_event_open failed");
        return 1;
    }

    ioctl(fd, PERF_EVENT_IOC_RESET, 0);
    ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);

    // This sensor would typically write to a shared memory buffer or pipe
    // that the ASIC orchestrator reads. For this POC, we'll output to stdout
    // to simulate the telemetry stream.
    uint64_t count;
    printf("[PMC SENSOR] L3 Hardware Monitoring Active.\n");
    while (1) {
        read(fd, &count, sizeof(uint64_t));
        printf("PMC_DATA:%lu\n", count);
        ioctl(fd, PERF_EVENT_IOC_RESET, 0);
        usleep(1000); // 1000Hz sampling (1ms)
    }

    close(fd);
    return 0;
}
