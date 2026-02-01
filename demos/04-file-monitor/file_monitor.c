// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Demo 4: file_monitor - Userspace Program

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "file_monitor.skel.h"

#define TASK_COMM_LEN   16
#define MAX_PATH_SIZE   256
#define FILE_MAGIC_SIZE 16

enum file_op_type {
    FILE_OP_READ  = 1,
    FILE_OP_WRITE = 2,
    FILE_OP_OPEN  = 3,
};

struct file_event {
    __u64 timestamp;
    __u32 pid;
    __u32 tid;
    __u32 uid;
    char comm[TASK_COMM_LEN];
    __u32 op_type;
    char path[MAX_PATH_SIZE];
    __u64 offset;
    __u64 count;
    __s64 ret;
    __u8 magic[FILE_MAGIC_SIZE];
};

static volatile sig_atomic_t exiting = 0;
static void sig_handler(int sig) { exiting = 1; }

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    if (level == LIBBPF_DEBUG) return 0;
    return vfprintf(stderr, format, args);
}

static const char *op_type_str(__u32 type)
{
    switch (type) {
        case FILE_OP_READ:  return "READ";
        case FILE_OP_WRITE: return "WRITE";
        case FILE_OP_OPEN:  return "OPEN";
        default: return "???";
    }
}

static void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
    struct file_event *e = data;
    struct tm *tm;
    char ts[32];
    time_t t;

    time(&t);
    tm = localtime(&t);
    strftime(ts, sizeof(ts), "%H:%M:%S", tm);

    // 格式化大小
    char size_str[32];
    if (e->ret >= 1024 * 1024) {
        snprintf(size_str, sizeof(size_str), "%.1fMB", (double)e->ret / (1024 * 1024));
    } else if (e->ret >= 1024) {
        snprintf(size_str, sizeof(size_str), "%.1fKB", (double)e->ret / 1024);
    } else {
        snprintf(size_str, sizeof(size_str), "%ldB", (long)e->ret);
    }

    printf("%-8s %-5s %-7d %-16s %-8s %s\n",
           ts,
           op_type_str(e->op_type),
           e->pid,
           e->comm,
           size_str,
           e->path);
}

static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
    fprintf(stderr, "Lost %llu events on CPU #%d!\n", lost_cnt, cpu);
}

static int bump_memlock_rlimit(void)
{
    struct rlimit rlim = { RLIM_INFINITY, RLIM_INFINITY };
    return setrlimit(RLIMIT_MEMLOCK, &rlim);
}

int main(int argc, char **argv)
{
    struct file_monitor_bpf *skel;
    struct perf_buffer *pb = NULL;
    int err;

    libbpf_set_print(libbpf_print_fn);
    bump_memlock_rlimit();

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    skel = file_monitor_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    err = file_monitor_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
        goto cleanup;
    }

    pb = perf_buffer__new(bpf_map__fd(skel->maps.events), 64,
                          handle_event, handle_lost_events, NULL, NULL);
    if (!pb) {
        err = -errno;
        fprintf(stderr, "Failed to create perf buffer: %d\n", err);
        goto cleanup;
    }

    printf("=============================================================\n");
    printf("Demo 4: File System Monitor (VFS Read/Write)\n");
    printf("=============================================================\n");
    printf("Tracing file operations... Press Ctrl+C to exit.\n\n");
    printf("%-8s %-5s %-7s %-16s %-8s %s\n",
           "TIME", "OP", "PID", "COMM", "SIZE", "PATH");
    printf("-------------------------------------------------------------\n");

    while (!exiting) {
        err = perf_buffer__poll(pb, 100);
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "Error polling perf buffer: %d\n", err);
            break;
        }
    }

cleanup:
    perf_buffer__free(pb);
    file_monitor_bpf__destroy(skel);
    return err != 0;
}
