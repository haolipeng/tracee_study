// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//
// Demo 3: process_tree - Userspace Program

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

#include "process_tree.skel.h"

#define TASK_COMM_LEN    16
#define MAX_FILENAME_LEN 256

enum process_event_type {
    EVENT_FORK = 1,
    EVENT_EXEC = 2,
    EVENT_EXIT = 3,
};

struct process_event {
    __u64 timestamp;
    __u32 event_type;
    __u32 pid;
    __u32 tid;
    __u32 ppid;
    __u32 uid;
    char comm[TASK_COMM_LEN];
    __u32 child_pid;
    __u32 child_tid;
    char filename[MAX_FILENAME_LEN];
    int exit_code;
};

static volatile sig_atomic_t exiting = 0;

static void sig_handler(int sig) { exiting = 1; }

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    if (level == LIBBPF_DEBUG) return 0;
    return vfprintf(stderr, format, args);
}

static const char *event_type_str(__u32 type)
{
    switch (type) {
        case EVENT_FORK: return "FORK";
        case EVENT_EXEC: return "EXEC";
        case EVENT_EXIT: return "EXIT";
        default: return "UNKNOWN";
    }
}

static void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
    struct process_event *e = data;
    struct tm *tm;
    char ts[32];
    time_t t;

    time(&t);
    tm = localtime(&t);
    strftime(ts, sizeof(ts), "%H:%M:%S", tm);

    // 根据事件类型格式化输出
    switch (e->event_type) {
        case EVENT_FORK:
            printf("%-8s [%-4s] %-16s PID=%-7d PPID=%-7d -> child PID=%d\n",
                   ts, event_type_str(e->event_type), e->comm,
                   e->pid, e->ppid, e->child_pid);
            break;

        case EVENT_EXEC:
            printf("%-8s [%-4s] %-16s PID=%-7d PPID=%-7d -> %s\n",
                   ts, event_type_str(e->event_type), e->comm,
                   e->pid, e->ppid, e->filename);
            break;

        case EVENT_EXIT:
            printf("%-8s [%-4s] %-16s PID=%-7d PPID=%-7d exit_code=%d\n",
                   ts, event_type_str(e->event_type), e->comm,
                   e->pid, e->ppid, e->exit_code >> 8);  // 高8位是退出码
            break;

        default:
            printf("%-8s [????] Unknown event type %d\n", ts, e->event_type);
    }
}

static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
    fprintf(stderr, "Lost %llu events on CPU #%d!\n", lost_cnt, cpu);
}

static int bump_memlock_rlimit(void)
{
    struct rlimit rlim = { RLIM_INFINITY, RLIM_INFINITY };
    if (setrlimit(RLIMIT_MEMLOCK, &rlim)) {
        fprintf(stderr, "Failed to set RLIMIT_MEMLOCK: %s\n", strerror(errno));
        return -1;
    }
    return 0;
}

int main(int argc, char **argv)
{
    struct process_tree_bpf *skel;
    struct perf_buffer *pb = NULL;
    int err;

    libbpf_set_print(libbpf_print_fn);
    if (bump_memlock_rlimit()) return 1;

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    skel = process_tree_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    err = process_tree_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
        goto cleanup;
    }

    pb = perf_buffer__new(bpf_map__fd(skel->maps.events), 8,
                          handle_event, handle_lost_events, NULL, NULL);
    if (!pb) {
        err = -errno;
        fprintf(stderr, "Failed to create perf buffer: %d\n", err);
        goto cleanup;
    }

    printf("=============================================================\n");
    printf("Demo 3: Process Lifecycle Monitor (Fork/Exec/Exit)\n");
    printf("=============================================================\n");
    printf("Tracing process events... Press Ctrl+C to exit.\n\n");
    printf("%-8s %-6s %-16s %-12s\n", "TIME", "TYPE", "COMM", "DETAILS");
    printf("-------------------------------------------------------------\n");

    while (!exiting) {
        err = perf_buffer__poll(pb, 100);
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "Error polling perf buffer: %d\n", err);
            break;
        }
    }

    printf("\nExiting...\n");

cleanup:
    perf_buffer__free(pb);
    process_tree_bpf__destroy(skel);
    return err != 0;
}
