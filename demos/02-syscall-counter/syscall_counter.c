// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//
// Demo 2: syscall_counter - Userspace Program
//
// 功能:
//   1. 加载 BPF 程序
//   2. 定期读取 syscall_count_map
//   3. 显示 Top 10 系统调用统计

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "syscall_counter.skel.h"

// ============================================================================
// Syscall Names (x86_64)
// ============================================================================

// 常见系统调用名称 (简化版)
// 完整列表参考: /usr/include/asm/unistd_64.h
static const char *syscall_names[] = {
    [0]   = "read",
    [1]   = "write",
    [2]   = "open",
    [3]   = "close",
    [4]   = "stat",
    [5]   = "fstat",
    [6]   = "lstat",
    [7]   = "poll",
    [8]   = "lseek",
    [9]   = "mmap",
    [10]  = "mprotect",
    [11]  = "munmap",
    [12]  = "brk",
    [13]  = "rt_sigaction",
    [14]  = "rt_sigprocmask",
    [15]  = "rt_sigreturn",
    [16]  = "ioctl",
    [17]  = "pread64",
    [18]  = "pwrite64",
    [19]  = "readv",
    [20]  = "writev",
    [21]  = "access",
    [22]  = "pipe",
    [23]  = "select",
    [24]  = "sched_yield",
    [25]  = "mremap",
    [26]  = "msync",
    [27]  = "mincore",
    [28]  = "madvise",
    [29]  = "shmget",
    [30]  = "shmat",
    [31]  = "shmctl",
    [32]  = "dup",
    [33]  = "dup2",
    [34]  = "pause",
    [35]  = "nanosleep",
    [36]  = "getitimer",
    [37]  = "alarm",
    [38]  = "setitimer",
    [39]  = "getpid",
    [40]  = "sendfile",
    [41]  = "socket",
    [42]  = "connect",
    [43]  = "accept",
    [44]  = "sendto",
    [45]  = "recvfrom",
    [46]  = "sendmsg",
    [47]  = "recvmsg",
    [48]  = "shutdown",
    [49]  = "bind",
    [50]  = "listen",
    [51]  = "getsockname",
    [52]  = "getpeername",
    [53]  = "socketpair",
    [54]  = "setsockopt",
    [55]  = "getsockopt",
    [56]  = "clone",
    [57]  = "fork",
    [58]  = "vfork",
    [59]  = "execve",
    [60]  = "exit",
    [61]  = "wait4",
    [62]  = "kill",
    [63]  = "uname",
    [72]  = "fcntl",
    [78]  = "getdents",
    [79]  = "getcwd",
    [80]  = "chdir",
    [89]  = "readlink",
    [102] = "getuid",
    [104] = "getgid",
    [107] = "geteuid",
    [108] = "getegid",
    [110] = "getppid",
    [157] = "prctl",
    [186] = "gettid",
    [202] = "futex",
    [217] = "getdents64",
    [228] = "clock_gettime",
    [230] = "clock_nanosleep",
    [231] = "exit_group",
    [232] = "epoll_wait",
    [233] = "epoll_ctl",
    [257] = "openat",
    [262] = "newfstatat",
    [270] = "pselect6",
    [271] = "ppoll",
    [281] = "epoll_pwait",
    [291] = "epoll_create1",
    [292] = "dup3",
    [293] = "pipe2",
    [302] = "prlimit64",
    [318] = "getrandom",
    [332] = "statx",
    [435] = "clone3",
};

#define MAX_SYSCALL_NR 512

static const char *get_syscall_name(__u32 nr)
{
    if (nr < sizeof(syscall_names) / sizeof(syscall_names[0]) && syscall_names[nr])
        return syscall_names[nr];
    return "unknown";
}

// ============================================================================
// Global State
// ============================================================================

static volatile sig_atomic_t exiting = 0;

static void sig_handler(int sig)
{
    exiting = 1;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    if (level == LIBBPF_DEBUG)
        return 0;
    return vfprintf(stderr, format, args);
}

// ============================================================================
// Statistics Display
// ============================================================================

struct syscall_stat {
    __u32 nr;
    __u64 count;
};

// 比较函数: 按调用次数降序排序
static int compare_stats(const void *a, const void *b)
{
    const struct syscall_stat *sa = a;
    const struct syscall_stat *sb = b;
    if (sa->count < sb->count) return 1;
    if (sa->count > sb->count) return -1;
    return 0;
}

static void print_stats(int map_fd, int top_n)
{
    struct syscall_stat stats[MAX_SYSCALL_NR];
    int count = 0;

    // 遍历 map，收集所有统计数据
    __u32 key, next_key;
    __u64 value;

    key = 0;
    while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
        if (bpf_map_lookup_elem(map_fd, &next_key, &value) == 0) {
            if (count < MAX_SYSCALL_NR) {
                stats[count].nr = next_key;
                stats[count].count = value;
                count++;
            }
        }
        key = next_key;
    }
    // 处理第一个 key
    key = 0;
    if (bpf_map_lookup_elem(map_fd, &key, &value) == 0) {
        // 检查是否已添加
        int found = 0;
        for (int i = 0; i < count; i++) {
            if (stats[i].nr == 0) {
                found = 1;
                break;
            }
        }
        if (!found && count < MAX_SYSCALL_NR) {
            stats[count].nr = 0;
            stats[count].count = value;
            count++;
        }
    }

    if (count == 0) {
        printf("No syscalls recorded yet.\n");
        return;
    }

    // 排序
    qsort(stats, count, sizeof(stats[0]), compare_stats);

    // 打印 Top N
    printf("\033[2J\033[H");  // 清屏
    printf("=============================================================\n");
    printf("Demo 2: System Call Counter (Top %d)\n", top_n);
    printf("=============================================================\n");
    printf("%-8s | %-20s | %-15s\n", "SYSCALL#", "NAME", "COUNT");
    printf("-------------------------------------------------------------\n");

    __u64 total = 0;
    for (int i = 0; i < count && i < top_n; i++) {
        printf("%-8u | %-20s | %-15llu\n",
               stats[i].nr,
               get_syscall_name(stats[i].nr),
               stats[i].count);
        total += stats[i].count;
    }

    printf("-------------------------------------------------------------\n");
    printf("Total syscalls (top %d): %llu\n", top_n, total);
    printf("\nPress Ctrl+C to exit. Refreshing every 2 seconds...\n");
}

// ============================================================================
// Main
// ============================================================================

static int bump_memlock_rlimit(void)
{
    struct rlimit rlim_new = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };

    if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
        fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK: %s\n", strerror(errno));
        return -1;
    }
    return 0;
}

int main(int argc, char **argv)
{
    struct syscall_counter_bpf *skel;
    int err;

    libbpf_set_print(libbpf_print_fn);

    if (bump_memlock_rlimit())
        return 1;

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    // 打开并加载 BPF 程序
    skel = syscall_counter_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    // 附加 BPF 程序
    err = syscall_counter_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
        goto cleanup;
    }

    printf("Successfully started! Collecting syscall statistics...\n");
    sleep(1);

    // 主循环: 定期打印统计
    int map_fd = bpf_map__fd(skel->maps.syscall_count_map);

    while (!exiting) {
        print_stats(map_fd, 15);  // 显示 Top 15
        sleep(2);
    }

    printf("\nExiting...\n");

cleanup:
    syscall_counter_bpf__destroy(skel);
    return err != 0;
}
