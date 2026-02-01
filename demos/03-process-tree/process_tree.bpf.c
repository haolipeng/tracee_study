// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//
// Demo 3: process_tree - Process Lifecycle Monitoring
//
// 学习目标:
//   1. 使用 sched 类 raw_tracepoint 追踪进程生命周期
//   2. 掌握 BPF_CORE_READ 宏读取内核结构
//   3. 理解 task_struct 数据结构
//   4. 学习进程树构建思路
//
// 参考 Tracee 代码:
//   - pkg/ebpf/c/tracee.bpf.c:602-757 (sched_process_fork)
//   - pkg/ebpf/c/tracee.bpf.c:1383-1468 (sched_process_exec)
//   - pkg/ebpf/c/tracee.bpf.c:1524-1583 (sched_process_exit)
//   - pkg/ebpf/c/common/task.h (task_struct 读取辅助函数)
//
// Git Commit 学习:
//   - 5a727b30: 线程栈识别算法改进

#include "common.h"

// ============================================================================
// Event Types
// ============================================================================

enum process_event_type {
    EVENT_FORK = 1,
    EVENT_EXEC = 2,
    EVENT_EXIT = 3,
};

// ============================================================================
// Event Structure
// ============================================================================

struct process_event {
    // 基础信息
    u64 timestamp;
    u32 event_type;          // fork/exec/exit

    // 当前进程信息
    u32 pid;
    u32 tid;
    u32 ppid;
    u32 uid;
    char comm[TASK_COMM_LEN];

    // fork 特定: 子进程信息
    u32 child_pid;
    u32 child_tid;

    // exec 特定: 文件名
    char filename[MAX_FILENAME_LEN];

    // exit 特定: 退出码
    int exit_code;
};

// ============================================================================
// BPF Maps
// ============================================================================

// Perf event array for output
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
} events SEC(".maps");

// Process info cache (for building tree relationships)
// 参考: Tracee 的 proc_info_map
struct proc_info {
    u32 pid;
    u32 ppid;
    u64 start_time;
    char comm[TASK_COMM_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);   // pid
    __type(value, struct proc_info);
} proc_info_map SEC(".maps");

// ============================================================================
// Helper Functions
// ============================================================================

// 从 task_struct 读取 PID (tgid)
// 参考: Tracee pkg/ebpf/c/common/task.h
statfunc u32 get_task_pid(struct task_struct *task)
{
    return BPF_CORE_READ(task, tgid);
}

// 从 task_struct 读取 TID (pid)
statfunc u32 get_task_tid(struct task_struct *task)
{
    return BPF_CORE_READ(task, pid);
}

// 从 task_struct 读取 PPID
statfunc u32 get_task_ppid(struct task_struct *task)
{
    struct task_struct *parent = BPF_CORE_READ(task, real_parent);
    return BPF_CORE_READ(parent, tgid);
}

// 从 task_struct 读取 UID
statfunc u32 get_task_uid(struct task_struct *task)
{
    // task->cred->uid.val
    struct cred *cred = BPF_CORE_READ(task, cred);
    return BPF_CORE_READ(cred, uid.val);
}

// 从 task_struct 读取启动时间
statfunc u64 get_task_start_time(struct task_struct *task)
{
    return BPF_CORE_READ(task, start_time);
}

// ============================================================================
// Raw Tracepoint: sched_process_fork
// ============================================================================

// fork 事件追踪
// 参考: Tracee pkg/ebpf/c/tracee.bpf.c:602-757
SEC("raw_tracepoint/sched_process_fork")
int trace_fork(struct bpf_raw_tracepoint_args *ctx)
{
    struct process_event event = {};
    event.event_type = EVENT_FORK;
    event.timestamp = bpf_ktime_get_ns();

    // raw_tracepoint/sched_process_fork 参数:
    //   ctx->args[0] = struct task_struct *parent
    //   ctx->args[1] = struct task_struct *child
    struct task_struct *parent = (struct task_struct *)ctx->args[0];
    struct task_struct *child = (struct task_struct *)ctx->args[1];

    // 填充父进程信息
    event.pid = get_task_pid(parent);
    event.tid = get_task_tid(parent);
    event.ppid = get_task_ppid(parent);
    event.uid = get_task_uid(parent);
    bpf_probe_read_kernel_str(&event.comm, sizeof(event.comm),
                              BPF_CORE_READ(parent, comm));

    // 填充子进程信息
    event.child_pid = get_task_pid(child);
    event.child_tid = get_task_tid(child);

    // 更新 proc_info_map: 记录子进程
    struct proc_info info = {
        .pid = event.child_pid,
        .ppid = event.pid,
        .start_time = get_task_start_time(child),
    };
    bpf_probe_read_kernel_str(&info.comm, sizeof(info.comm),
                              BPF_CORE_READ(child, comm));
    bpf_map_update_elem(&proc_info_map, &event.child_pid, &info, BPF_ANY);

    // 发送事件
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));

    return 0;
}

// ============================================================================
// Raw Tracepoint: sched_process_exec
// ============================================================================

// exec 事件追踪
// 参考: Tracee pkg/ebpf/c/tracee.bpf.c:1383-1468
SEC("raw_tracepoint/sched_process_exec")
int trace_exec(struct bpf_raw_tracepoint_args *ctx)
{
    struct process_event event = {};
    event.event_type = EVENT_EXEC;
    event.timestamp = bpf_ktime_get_ns();

    // raw_tracepoint/sched_process_exec 参数:
    //   ctx->args[0] = struct task_struct *task
    //   ctx->args[1] = pid_t old_pid
    //   ctx->args[2] = struct linux_binprm *bprm
    struct task_struct *task = (struct task_struct *)ctx->args[0];
    struct linux_binprm *bprm = (struct linux_binprm *)ctx->args[2];

    // 填充进程信息
    event.pid = get_task_pid(task);
    event.tid = get_task_tid(task);
    event.ppid = get_task_ppid(task);
    event.uid = get_task_uid(task);
    bpf_probe_read_kernel_str(&event.comm, sizeof(event.comm),
                              BPF_CORE_READ(task, comm));

    // 读取执行的文件名
    // bprm->filename 是文件路径
    const char *filename = BPF_CORE_READ(bprm, filename);
    bpf_probe_read_kernel_str(&event.filename, sizeof(event.filename), filename);

    // 更新 proc_info_map: 更新 comm
    struct proc_info *info = bpf_map_lookup_elem(&proc_info_map, &event.pid);
    if (info) {
        bpf_probe_read_kernel_str(&info->comm, sizeof(info->comm),
                                  BPF_CORE_READ(task, comm));
    }

    // 发送事件
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));

    return 0;
}

// ============================================================================
// Raw Tracepoint: sched_process_exit
// ============================================================================

// exit 事件追踪
// 参考: Tracee pkg/ebpf/c/tracee.bpf.c:1524-1583
SEC("raw_tracepoint/sched_process_exit")
int trace_exit(struct bpf_raw_tracepoint_args *ctx)
{
    struct process_event event = {};
    event.event_type = EVENT_EXIT;
    event.timestamp = bpf_ktime_get_ns();

    // raw_tracepoint/sched_process_exit 参数:
    //   ctx->args[0] = struct task_struct *task
    struct task_struct *task = (struct task_struct *)ctx->args[0];

    // 填充进程信息
    event.pid = get_task_pid(task);
    event.tid = get_task_tid(task);
    event.ppid = get_task_ppid(task);
    event.uid = get_task_uid(task);
    bpf_probe_read_kernel_str(&event.comm, sizeof(event.comm),
                              BPF_CORE_READ(task, comm));

    // 获取退出码
    // task->exit_code 包含退出状态
    event.exit_code = BPF_CORE_READ(task, exit_code);

    // 只在主线程退出时清理 proc_info_map
    // (tid == pid 表示主线程)
    if (event.tid == event.pid) {
        bpf_map_delete_elem(&proc_info_map, &event.pid);
    }

    // 发送事件
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));

    return 0;
}

// ============================================================================
// License
// ============================================================================

char LICENSE[] SEC("license") = "Dual BSD/GPL";
