// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Demo 7: mprotect_alert - Userspace Program

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

#include "mprotect_alert.skel.h"

#define TASK_COMM_LEN 16
#define PROT_READ   0x1
#define PROT_WRITE  0x2
#define PROT_EXEC   0x4

enum alert_type {
    ALERT_MMAP_W_X    = 1,
    ALERT_MPROT_X_ADD = 2,
    ALERT_MPROT_W_ADD = 3,
    ALERT_MPROT_W_REM = 4,
};

struct mprotect_event {
    __u64 timestamp;
    __u32 pid;
    __u32 tid;
    __u32 uid;
    char comm[TASK_COMM_LEN];
    __u64 addr;
    __u64 len;
    __u32 prot;
    __u32 old_prot;
    __u32 alert_type;
};

static volatile sig_atomic_t exiting = 0;
static void sig_handler(int sig) { exiting = 1; }

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    if (level == LIBBPF_DEBUG) return 0;
    return vfprintf(stderr, format, args);
}

static const char *alert_type_str(__u32 type)
{
    switch (type) {
        case ALERT_MMAP_W_X:    return "MMAP_W+X";
        case ALERT_MPROT_X_ADD: return "MPROT_+X";
        case ALERT_MPROT_W_ADD: return "MPROT_+WX";
        case ALERT_MPROT_W_REM: return "MPROT_-W";
        default: return "UNKNOWN";
    }
}

static void prot_to_str(__u32 prot, char *buf, size_t size)
{
    snprintf(buf, size, "%c%c%c",
             (prot & PROT_READ)  ? 'R' : '-',
             (prot & PROT_WRITE) ? 'W' : '-',
             (prot & PROT_EXEC)  ? 'X' : '-');
}

static void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
    struct mprotect_event *e = data;
    struct tm *tm;
    char ts[32];
    char prot_str[8], old_prot_str[8];
    time_t t;

    time(&t);
    tm = localtime(&t);
    strftime(ts, sizeof(ts), "%H:%M:%S", tm);

    prot_to_str(e->prot, prot_str, sizeof(prot_str));
    prot_to_str(e->old_prot, old_prot_str, sizeof(old_prot_str));

    // 高危告警用红色
    const char *color = "";
    const char *reset = "";
    if (e->alert_type == ALERT_MMAP_W_X || e->alert_type == ALERT_MPROT_W_ADD) {
        color = "\033[31m";
        reset = "\033[0m";
    }

    printf("%s%-8s %-10s %-7d %-16s 0x%-12lx %s->%s%s\n",
           color, ts,
           alert_type_str(e->alert_type),
           e->pid,
           e->comm,
           e->addr,
           old_prot_str, prot_str,
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
    struct mprotect_alert_bpf *skel;
    struct perf_buffer *pb = NULL;
    int err;

    libbpf_set_print(libbpf_print_fn);
    bump_memlock_rlimit();

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    skel = mprotect_alert_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    err = mprotect_alert_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
        goto cleanup;
    }

    pb = perf_buffer__new(bpf_map__fd(skel->maps.events), 16,
                          handle_event, handle_lost_events, NULL, NULL);
    if (!pb) {
        err = -errno;
        fprintf(stderr, "Failed to create perf buffer: %d\n", err);
        goto cleanup;
    }

    printf("=============================================================\n");
    printf("Demo 7: Memory Protection Alert (W^X Violation Detection)\n");
    printf("=============================================================\n");
    printf("Detecting suspicious memory protection changes...\n");
    printf("(W+X violations shown in red)\n\n");
    printf("%-8s %-10s %-7s %-16s %-14s %s\n",
           "TIME", "ALERT", "PID", "COMM", "ADDRESS", "PROT");
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
    mprotect_alert_bpf__destroy(skel);
    return err != 0;
}
