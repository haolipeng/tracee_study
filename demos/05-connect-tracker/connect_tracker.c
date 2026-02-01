// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Demo 5: connect_tracker - Userspace Program

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "connect_tracker.skel.h"

#define TASK_COMM_LEN 16
#define AF_INET  2
#define AF_INET6 10
#define SOCK_STREAM 1
#define SOCK_DGRAM  2

struct connect_event {
    __u64 timestamp;
    __u32 pid;
    __u32 tid;
    __u32 uid;
    char comm[TASK_COMM_LEN];
    __u16 af;
    __u16 protocol;
    __u16 sport;
    __u16 dport;
    union {
        __u32 saddr_v4;
        __u8  saddr_v6[16];
    };
    union {
        __u32 daddr_v4;
        __u8  daddr_v6[16];
    };
};

static volatile sig_atomic_t exiting = 0;
static void sig_handler(int sig) { exiting = 1; }

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    if (level == LIBBPF_DEBUG) return 0;
    return vfprintf(stderr, format, args);
}

static const char *proto_str(__u16 proto)
{
    return proto == SOCK_STREAM ? "TCP" : "UDP";
}

static void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
    struct connect_event *e = data;
    char saddr[INET6_ADDRSTRLEN] = {0};
    char daddr[INET6_ADDRSTRLEN] = {0};
    struct tm *tm;
    char ts[32];
    time_t t;

    time(&t);
    tm = localtime(&t);
    strftime(ts, sizeof(ts), "%H:%M:%S", tm);

    // 转换 IP 地址为字符串
    if (e->af == AF_INET) {
        inet_ntop(AF_INET, &e->saddr_v4, saddr, sizeof(saddr));
        inet_ntop(AF_INET, &e->daddr_v4, daddr, sizeof(daddr));
    } else if (e->af == AF_INET6) {
        inet_ntop(AF_INET6, e->saddr_v6, saddr, sizeof(saddr));
        inet_ntop(AF_INET6, e->daddr_v6, daddr, sizeof(daddr));
    }

    // 如果源地址为空，显示 *
    if (saddr[0] == '\0' || strcmp(saddr, "0.0.0.0") == 0)
        strcpy(saddr, "*");

    printf("%-8s %-3s %-7d %-16s %s:%-5d -> %s:%d\n",
           ts,
           proto_str(e->protocol),
           e->pid,
           e->comm,
           saddr, e->sport,
           daddr, e->dport);
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
    struct connect_tracker_bpf *skel;
    struct perf_buffer *pb = NULL;
    int err;

    libbpf_set_print(libbpf_print_fn);
    bump_memlock_rlimit();

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    skel = connect_tracker_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    err = connect_tracker_bpf__attach(skel);
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
    printf("Demo 5: TCP/UDP Connection Tracker\n");
    printf("=============================================================\n");
    printf("Tracing network connections... Press Ctrl+C to exit.\n\n");
    printf("%-8s %-3s %-7s %-16s %s\n",
           "TIME", "PRO", "PID", "COMM", "CONNECTION");
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
    connect_tracker_bpf__destroy(skel);
    return err != 0;
}
