// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//
// Demo 2: syscall_counter - System Call Counter
//
// 学习目标:
//   1. 使用 raw_tracepoint 追踪所有系统调用
//   2. 掌握 BPF Hash Map 的使用
//   3. 理解原子操作 __sync_fetch_and_add
//   4. 学习 Tracee 的内联汇编技巧 (update_min)
//
// 参考 Tracee 代码:
//   - pkg/ebpf/c/tracee.bpf.c:45-60 (sys_enter)
//   - pkg/ebpf/c/maps.h (各种 map 定义)
//
// Git Commit 学习:
//   - 9f591d33: 内联汇编约束 bug
//
// 运行方式:
//   sudo ./syscall_counter

#include "common.h"

// ============================================================================
// Constants
// ============================================================================

// x86_64 最大系统调用号 (参考 /usr/include/asm/unistd_64.h)
#define MAX_SYSCALL_NR  512

// ============================================================================
// BPF Maps
// ============================================================================

// Hash Map: 统计每个系统调用的次数
// Key: 系统调用号
// Value: 调用次数
// 参考: Tracee pkg/ebpf/c/maps.h
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_SYSCALL_NR);
    __type(key, u32);       // syscall number
    __type(value, u64);     // count
} syscall_count_map SEC(".maps");

// Per-CPU Array: 用于存储每个 CPU 的临时数据
// 这是 Tracee 常用的模式，避免栈空间限制
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} scratch_map SEC(".maps");

// ============================================================================
// Inline Assembly Example (from Tracee)
// ============================================================================

// 这是 Tracee 中用于边界检查的宏
// Git Commit 9f591d33 修复了这个宏的 bug
//
// 问题: 原始版本缺少输出约束，导致只修改寄存器副本
// 修复: 添加 "+r" 输出约束
//
// 学习点: 理解内联汇编在 eBPF 中的应用
//         用于绕过验证器的某些限制
#define update_min(var, max_val)                                               \
    asm volatile("if %[v] <= %[m] goto +1;\n"                                  \
                 "%[v] = %[m];\n"                                              \
                 : [v] "+r"(var)                                               \
                 : [m] "r"(max_val))

// ============================================================================
// Raw Tracepoint: sys_enter
// ============================================================================

// raw_tracepoint 比 tracepoint 更底层
// 优点: 性能更好，可以访问原始参数
// 缺点: 参数是无类型的 (void *)
//
// 参考: Tracee pkg/ebpf/c/tracee.bpf.c:45-60
SEC("raw_tracepoint/sys_enter")
int trace_sys_enter(struct bpf_raw_tracepoint_args *ctx)
{
    // -------------------------------------------------------------------------
    // Step 1: 获取系统调用号
    // -------------------------------------------------------------------------

    // raw_tracepoint/sys_enter 的参数:
    //   ctx->args[0] = struct pt_regs *regs
    //   ctx->args[1] = long syscall_id
    u32 syscall_id = (u32)ctx->args[1];

    // 边界检查: 确保系统调用号在有效范围内
    // 使用 Tracee 风格的 update_min 宏
    // 如果 syscall_id > MAX_SYSCALL_NR - 1，则设置为 MAX_SYSCALL_NR - 1
    u32 max_syscall = MAX_SYSCALL_NR - 1;
    update_min(syscall_id, max_syscall);

    // -------------------------------------------------------------------------
    // Step 2: 更新计数器 (原子操作)
    // -------------------------------------------------------------------------

    // 查找当前系统调用的计数
    u64 *count = bpf_map_lookup_elem(&syscall_count_map, &syscall_id);

    if (count) {
        // 已存在: 原子递增
        // __sync_fetch_and_add 是原子操作，多 CPU 安全
        __sync_fetch_and_add(count, 1);
    } else {
        // 不存在: 初始化为 1
        u64 init_count = 1;
        bpf_map_update_elem(&syscall_count_map, &syscall_id, &init_count, BPF_ANY);
    }

    return 0;
}

// ============================================================================
// Optional: Per-process Syscall Counting
// ============================================================================

// 扩展: 按进程统计系统调用
// Key: (pid << 32) | syscall_id
// 这展示了如何创建复合键

struct proc_syscall_key {
    u32 pid;
    u32 syscall_id;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);  // LRU 自动清理旧条目
    __uint(max_entries, 10240);
    __type(key, struct proc_syscall_key);
    __type(value, u64);
} proc_syscall_map SEC(".maps");

SEC("raw_tracepoint/sys_enter_proc")
int trace_sys_enter_per_proc(struct bpf_raw_tracepoint_args *ctx)
{
    u32 syscall_id = (u32)ctx->args[1];
    u32 max_syscall = MAX_SYSCALL_NR - 1;
    update_min(syscall_id, max_syscall);

    // 获取 PID
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    // 创建复合键
    struct proc_syscall_key key = {
        .pid = pid,
        .syscall_id = syscall_id,
    };

    // 更新计数
    u64 *count = bpf_map_lookup_elem(&proc_syscall_map, &key);
    if (count) {
        __sync_fetch_and_add(count, 1);
    } else {
        u64 init_count = 1;
        bpf_map_update_elem(&proc_syscall_map, &key, &init_count, BPF_ANY);
    }

    return 0;
}

// ============================================================================
// License
// ============================================================================

char LICENSE[] SEC("license") = "Dual BSD/GPL";
