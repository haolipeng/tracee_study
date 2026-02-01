// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Demo 6: cap_check - Userspace Program

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

#include "cap_check.skel.h"

#define TASK_COMM_LEN 16

struct cap_event {
    __u64 timestamp;
    __u32 pid;
    __u32 tid;
    __u32 uid;
    char comm[TASK_COMM_LEN];
    int cap;
    int cap_opt;
    int audit;
};

// Capability 名称表
static const char *cap_names[] = {
    [0]  = "CAP_CHOWN",
    [1]  = "CAP_DAC_OVERRIDE",
    [2]  = "CAP_DAC_READ_SEARCH",
    [3]  = "CAP_FOWNER",
    [4]  = "CAP_FSETID",
    [5]  = "CAP_KILL",
    [6]  = "CAP_SETGID",
    [7]  = "CAP_SETUID",
    [8]  = "CAP_SETPCAP",
    [9]  = "CAP_LINUX_IMMUTABLE",
    [10] = "CAP_NET_BIND_SERVICE",
    [11] = "CAP_NET_BROADCAST",
    [12] = "CAP_NET_ADMIN",
    [13] = "CAP_NET_RAW",
    [14] = "CAP_IPC_LOCK",
    [15] = "CAP_IPC_OWNER",
    [16] = "CAP_SYS_MODULE",
    [17] = "CAP_SYS_RAWIO",
    [18] = "CAP_SYS_CHROOT",
    [19] = "CAP_SYS_PTRACE",
    [20] = "CAP_SYS_PACCT",
    [21] = "CAP_SYS_ADMIN",
    [22] = "CAP_SYS_BOOT",
    [23] = "CAP_SYS_NICE",
    [24] = "CAP_SYS_RESOURCE",
    [25] = "CAP_SYS_TIME",
    [26] = "CAP_SYS_TTY_CONFIG",
    [27] = "CAP_MKNOD",
    [28] = "CAP_LEASE",
    [29] = "CAP_AUDIT_WRITE",
    [30] = "CAP_AUDIT_CONTROL",
    [31] = "CAP_SETFCAP",
    [32] = "CAP_MAC_OVERRIDE",
    [33] = "CAP_MAC_ADMIN",
    [34] = "CAP_SYSLOG",
    [35] = "CAP_WAKE_ALARM",
    [36] = "CAP_BLOCK_SUSPEND",
    [37] = "CAP_AUDIT_READ",
    [38] = "CAP_PERFMON",
    [39] = "CAP_BPF",
    [40] = "CAP_CHECKPOINT_RESTORE",
};

static const char *get_cap_name(int cap)
{
    if (cap >= 0 && cap < (int)(sizeof(cap_names)/sizeof(cap_names[0])) && cap_names[cap])
        return cap_names[cap];
    return "UNKNOWN";
}

// 高危 capability
static int is_dangerous_cap(int cap)
{
    switch (cap) {
        case 12: // CAP_NET_ADMIN
        case 13: // CAP_NET_RAW
        case 16: // CAP_SYS_MODULE
        case 17: // CAP_SYS_RAWIO
        case 19: // CAP_SYS_PTRACE
        case 21: // CAP_SYS_ADMIN
        case 39: // CAP_BPF
            return 1;
        default:
            return 0;
    }
}

static volatile sig_atomic_t exiting = 0;
static void sig_handler(int sig) { exiting = 1; }

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    if (level == LIBBPF_DEBUG) return 0;
    return vfprintf(stderr, format, args);
}

static void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
    struct cap_event *e = data;
    struct tm *tm;
    char ts[32];
    time_t t;

    time(&t);
    tm = localtime(&t);
    strftime(ts, sizeof(ts), "%H:%M:%S", tm);

    // 高危 capability 用红色标记
    const char *color = is_dangerous_cap(e->cap) ? "\033[31m" : "";
    const char *reset = is_dangerous_cap(e->cap) ? "\033[0m" : "";

    printf("%-8s %s%-7d %-16s %-25s%s\n",
           ts,
           color,
           e->pid,
           e->comm,
           get_cap_name(e->cap),
           reset);
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
    struct cap_check_bpf *skel;
    struct perf_buffer *pb = NULL;
    int err;

    libbpf_set_print(libbpf_print_fn);
    bump_memlock_rlimit();

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    skel = cap_check_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    err = cap_check_bpf__attach(skel);
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
    printf("Demo 6: Capability Check Monitor\n");
    printf("=============================================================\n");
    printf("Tracing capability checks... Press Ctrl+C to exit.\n");
    printf("(Dangerous capabilities shown in red)\n\n");
    printf("%-8s %-7s %-16s %-25s\n", "TIME", "PID", "COMM", "CAPABILITY");
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
    cap_check_bpf__destroy(skel);
    return err != 0;
}
