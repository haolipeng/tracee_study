// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//
// Demo 1: hello_exec - Userspace Program
//
// 这是用户态程序，负责:
//   1. 加载 eBPF 程序
//   2. 附加到 tracepoint
//   3. 读取 perf buffer 中的事件
//   4. 打印事件信息
//
// 编译: make demo1
// 运行: sudo ./01-hello-exec/hello_exec

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

// 包含生成的 skeleton 头文件
// 由 bpftool gen skeleton 命令生成
#include "hello_exec.skel.h"

// ============================================================================
// Constants (must match BPF side)
// ============================================================================

#define TASK_COMM_LEN     16
#define MAX_FILENAME_LEN  256

// ============================================================================
// Event Structure (must match BPF side exactly!)
// ============================================================================

struct exec_event {
    __u64 timestamp;
    __u32 pid;
    __u32 tid;
    __u32 ppid;
    __u32 uid;
    char comm[TASK_COMM_LEN];
    char filename[MAX_FILENAME_LEN];
    int retval;
};

// ============================================================================
// Global State
// ============================================================================

static volatile sig_atomic_t exiting = 0;

// Signal handler for graceful exit
static void sig_handler(int sig)
{
    exiting = 1;
}

// ============================================================================
// Libbpf Print Callback
// ============================================================================

// 自定义 libbpf 日志输出
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    // 只打印警告和错误
    if (level == LIBBPF_DEBUG)
        return 0;
    return vfprintf(stderr, format, args);
}

// ============================================================================
// Event Handler
// ============================================================================

// 处理从 perf buffer 收到的事件
static void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
    struct exec_event *e = data;
    struct tm *tm;
    char ts[32];
    time_t t;

    // 将纳秒时间戳转换为可读格式
    // 注意: bpf_ktime_get_ns 返回的是系统启动后的时间
    // 这里简单使用当前时间
    time(&t);
    tm = localtime(&t);
    strftime(ts, sizeof(ts), "%H:%M:%S", tm);

    // 打印事件信息
    // 格式: 时间 | PID | PPID | UID | COMM | FILENAME
    printf("%-8s | %-7d | %-7d | %-5d | %-16s | %s\n",
           ts,
           e->pid,
           e->ppid,
           e->uid,
           e->comm,
           e->filename);
}

// 处理丢失的事件
static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
    fprintf(stderr, "WARNING: Lost %llu events on CPU #%d!\n", lost_cnt, cpu);
}

// ============================================================================
// Resource Limit Helper
// ============================================================================

// 增加 RLIMIT_MEMLOCK 限制
// eBPF 程序和 maps 需要锁定内存
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

// ============================================================================
// Main
// ============================================================================

int main(int argc, char **argv)
{
    struct hello_exec_bpf *skel = NULL;
    struct perf_buffer *pb = NULL;
    int err;

    // -------------------------------------------------------------------------
    // Step 1: Setup
    // -------------------------------------------------------------------------

    // 设置 libbpf 日志回调
    libbpf_set_print(libbpf_print_fn);

    // 增加内存锁定限制
    if (bump_memlock_rlimit()) {
        return 1;
    }

    // 设置信号处理
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    // -------------------------------------------------------------------------
    // Step 2: Open and Load BPF Program
    // -------------------------------------------------------------------------

    // 打开 BPF 对象
    // xxx_bpf__open() 解析 ELF 文件，准备加载
    skel = hello_exec_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    // 加载 BPF 程序到内核
    // xxx_bpf__load() 实际加载程序和 maps
    err = hello_exec_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
        goto cleanup;
    }

    // -------------------------------------------------------------------------
    // Step 3: Attach BPF Program
    // -------------------------------------------------------------------------

    // 附加 BPF 程序到 tracepoint
    // xxx_bpf__attach() 将所有程序附加到它们的 hook 点
    err = hello_exec_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
        goto cleanup;
    }

    // -------------------------------------------------------------------------
    // Step 4: Setup Perf Buffer
    // -------------------------------------------------------------------------

    // 创建 perf buffer 以接收事件
    // 参数:
    //   map_fd      - events map 的文件描述符
    //   8           - 每个 CPU 的 buffer 页数 (8 * 4096 = 32KB)
    //   handle_event - 事件处理回调
    //   handle_lost_events - 丢失事件回调
    //   NULL        - 用户上下文
    //   NULL        - 选项
    pb = perf_buffer__new(bpf_map__fd(skel->maps.events),
                          8,
                          handle_event,
                          handle_lost_events,
                          NULL,
                          NULL);
    if (!pb) {
        err = -errno;
        fprintf(stderr, "Failed to create perf buffer: %d\n", err);
        goto cleanup;
    }

    // -------------------------------------------------------------------------
    // Step 5: Event Loop
    // -------------------------------------------------------------------------

    printf("=============================================================\n");
    printf("Demo 1: execve Tracing (Hello eBPF!)\n");
    printf("=============================================================\n");
    printf("Tracing execve system calls... Press Ctrl+C to exit.\n");
    printf("\n");
    printf("%-8s | %-7s | %-7s | %-5s | %-16s | %s\n",
           "TIME", "PID", "PPID", "UID", "COMM", "FILENAME");
    printf("-------------------------------------------------------------\n");

    // 主循环：轮询 perf buffer
    while (!exiting) {
        // perf_buffer__poll 等待事件
        // 参数: 超时时间 (毫秒), -1 表示无限等待
        // 返回: 处理的事件数，或负数表示错误
        err = perf_buffer__poll(pb, 100);  // 100ms 超时
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "Error polling perf buffer: %d\n", err);
            break;
        }
    }

    printf("\nExiting...\n");

cleanup:
    // -------------------------------------------------------------------------
    // Step 6: Cleanup
    // -------------------------------------------------------------------------

    perf_buffer__free(pb);
    hello_exec_bpf__destroy(skel);

    return err != 0;
}
