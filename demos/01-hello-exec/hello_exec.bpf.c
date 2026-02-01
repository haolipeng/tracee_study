// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//
// Demo 1: hello_exec - execve System Call Tracing
//
// 学习目标:
//   1. 理解 eBPF 程序基本结构 (SEC, LICENSE)
//   2. 使用 tracepoint 追踪系统调用
//   3. 使用 bpf_perf_event_output 向用户态发送事件
//   4. 理解 BPF_CORE_READ 宏的使用
//
// 参考 Tracee 代码:
//   - pkg/ebpf/c/tracee.bpf.c:364-482 (syscall__execve_enter)
//   - pkg/ebpf/c/common/arguments.h (参数保存模式)
//
// 运行方式:
//   sudo ./hello_exec

#include "common.h"

// ============================================================================
// Event Structure
// ============================================================================

// 定义 execve 事件结构
// 参考 Tracee 的 event_context_t 简化版
struct exec_event {
    // 基础信息
    u64 timestamp;
    u32 pid;
    u32 tid;
    u32 ppid;
    u32 uid;
    char comm[TASK_COMM_LEN];

    // execve 特定字段
    char filename[MAX_FILENAME_LEN];   // 执行的文件路径
    int retval;                         // 返回值 (exit 时填充)
};

// ============================================================================
// BPF Maps
// ============================================================================

// Perf event array for sending events to userspace
// 参考: Tracee pkg/ebpf/c/maps.h 中的 events map
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
} events SEC(".maps");

// ============================================================================
// Tracepoint: sys_enter_execve
// ============================================================================

// execve 系统调用参数结构 (从 /sys/kernel/debug/tracing/events/syscalls/sys_enter_execve/format 获取)
struct execve_args {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    int __syscall_nr;
    const char *filename;      // 要执行的文件路径
    const char *const *argv;   // 参数数组
    const char *const *envp;   // 环境变量数组
};

// 追踪 execve 系统调用入口
// SEC 宏定义程序类型和附加点
// 格式: tracepoint/<category>/<event>
SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve_enter(struct execve_args *ctx)
{
    struct exec_event event = {};

    // -------------------------------------------------------------------------
    // Step 1: 填充基础信息
    // -------------------------------------------------------------------------

    // 获取 PID 和 TID
    // bpf_get_current_pid_tgid() 返回 64 位值:
    //   高 32 位 = TGID (进程 ID, 用户空间所说的 PID)
    //   低 32 位 = PID (线程 ID, 用户空间所说的 TID)
    u64 pid_tgid = bpf_get_current_pid_tgid();
    event.pid = pid_tgid >> 32;
    event.tid = (u32)pid_tgid;

    // 获取 UID
    u64 uid_gid = bpf_get_current_uid_gid();
    event.uid = (u32)uid_gid;

    // 获取时间戳 (纳秒)
    event.timestamp = bpf_ktime_get_ns();

    // 获取进程名 (comm)
    // comm 是 task_struct 中的 16 字节字符串
    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    // 获取父进程 PID
    // 需要读取内核数据结构 task_struct
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    event.ppid = get_ppid(task);

    // -------------------------------------------------------------------------
    // Step 2: 读取 execve 参数 (filename)
    // -------------------------------------------------------------------------

    // 从用户空间读取文件名
    // ctx->filename 是用户空间指针, 需要用 bpf_probe_read_user_str
    // 注意: 这里使用 bpf_probe_read_user_str 而不是 bpf_probe_read_kernel_str
    // 因为 execve 的参数来自用户空间
    if (ctx->filename) {
        bpf_probe_read_user_str(&event.filename, sizeof(event.filename), ctx->filename);
    }

    // -------------------------------------------------------------------------
    // Step 3: 发送事件到用户态
    // -------------------------------------------------------------------------

    // bpf_perf_event_output 将事件发送到 perf buffer
    // 参数:
    //   ctx      - 当前上下文
    //   &events  - perf event array map
    //   BPF_F_CURRENT_CPU - 使用当前 CPU 的 buffer
    //   &event   - 要发送的数据
    //   sizeof(event) - 数据大小
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));

    return 0;
}

// ============================================================================
// License
// ============================================================================

// 所有 eBPF 程序都必须声明 license
// GPL 兼容的 license 才能使用所有 BPF helper 函数
char LICENSE[] SEC("license") = "Dual BSD/GPL";
