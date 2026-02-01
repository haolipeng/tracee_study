// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//
// Demo 7: mprotect_alert - Memory Protection Alert
//
// 学习目标:
//   1. 追踪内存保护变更 (mprotect)
//   2. 检测 W^X 违规 (可写可执行内存)
//   3. 理解内存保护机制
//   4. 学习安全检测策略
//
// 参考 Tracee 代码:
//   - pkg/ebpf/c/tracee.bpf.c:3534-3565 (security_mmap_addr)
//   - pkg/ebpf/c/tracee.bpf.c:3680-3779 (security_file_mprotect)
//   - pkg/ebpf/c/common/memory.h
//
// Git Commit 学习:
//   - 3ac936c9: Golang 堆检测精度修复

#include "common.h"

// ============================================================================
// Memory Protection Flags (from linux/mman.h)
// ============================================================================

#define PROT_READ   0x1
#define PROT_WRITE  0x2
#define PROT_EXEC   0x4
#define PROT_NONE   0x0

// VM flags
#define VM_READ     0x00000001
#define VM_WRITE    0x00000002
#define VM_EXEC     0x00000004
#define VM_SHARED   0x00000008

// ============================================================================
// Alert Types
// ============================================================================

enum alert_type {
    ALERT_MMAP_W_X    = 1,  // mmap 同时有 W 和 X
    ALERT_MPROT_X_ADD = 2,  // mprotect 添加 X 权限
    ALERT_MPROT_W_ADD = 3,  // mprotect 添加 W+X 权限
    ALERT_MPROT_W_REM = 4,  // mprotect 移除 W 但保持 X
};

// ============================================================================
// Event Structure
// ============================================================================

struct mprotect_event {
    u64 timestamp;
    u32 pid;
    u32 tid;
    u32 uid;
    char comm[TASK_COMM_LEN];

    u64 addr;           // 内存地址
    u64 len;            // 长度
    u32 prot;           // 新的保护标志
    u32 old_prot;       // 旧的保护标志 (mprotect)
    u32 alert_type;     // 告警类型
};

// ============================================================================
// BPF Maps
// ============================================================================

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
} events SEC(".maps");

// 保存 mprotect 参数
struct mprotect_args {
    u64 addr;
    size_t len;
    unsigned long prot;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);
    __type(value, struct mprotect_args);
} args_map SEC(".maps");

// ============================================================================
// Helper Functions
// ============================================================================

// 检查是否同时有写和执行权限 (W^X 违规)
statfunc bool is_wx_violation(unsigned long prot)
{
    return (prot & PROT_WRITE) && (prot & PROT_EXEC);
}

// 从 VMA 标志转换为保护标志
statfunc unsigned long vm_flags_to_prot(unsigned long vm_flags)
{
    unsigned long prot = 0;
    if (vm_flags & VM_READ)
        prot |= PROT_READ;
    if (vm_flags & VM_WRITE)
        prot |= PROT_WRITE;
    if (vm_flags & VM_EXEC)
        prot |= PROT_EXEC;
    return prot;
}

// ============================================================================
// Kprobe: security_mmap_addr (检测 W+X mmap)
// ============================================================================

// security_mmap_addr 在 mmap 时被调用
// 参考: Tracee pkg/ebpf/c/tracee.bpf.c:3534-3565
SEC("kprobe/security_mmap_addr")
int BPF_KPROBE(trace_mmap_addr, unsigned long addr)
{
    // 获取当前任务
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    // 从系统调用参数获取 prot
    // mmap 参数: addr, len, prot, flags, fd, offset
    // prot 是第 3 个参数 (索引 2)
    struct pt_regs *regs = (struct pt_regs *)PT_REGS_PARM1(ctx);
    if (!regs)
        return 0;

    // 这里简化处理，直接从 ctx 获取
    // 实际中需要根据架构获取正确的参数
    unsigned long prot = PT_REGS_PARM3(ctx);

    // 检查 W^X 违规
    if (!is_wx_violation(prot))
        return 0;

    // 填充事件
    struct mprotect_event event = {};
    event.timestamp = bpf_ktime_get_ns();
    u64 pid_tgid = bpf_get_current_pid_tgid();
    event.pid = pid_tgid >> 32;
    event.tid = (u32)pid_tgid;
    event.uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    event.addr = addr;
    event.prot = prot;
    event.alert_type = ALERT_MMAP_W_X;

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));

    return 0;
}

// ============================================================================
// Kprobe: security_file_mprotect (检测权限变更)
// ============================================================================

// security_file_mprotect 在 mprotect 时被调用
// 函数签名: int security_file_mprotect(struct vm_area_struct *vma,
//                                       unsigned long reqprot,
//                                       unsigned long prot)
//
// 参考: Tracee pkg/ebpf/c/tracee.bpf.c:3680-3779
SEC("kprobe/security_file_mprotect")
int BPF_KPROBE(trace_mprotect, struct vm_area_struct *vma,
               unsigned long reqprot, unsigned long prot)
{
    // 获取旧的保护标志
    unsigned long old_vm_flags = BPF_CORE_READ(vma, vm_flags);
    unsigned long old_prot = vm_flags_to_prot(old_vm_flags);

    // 检查各种告警条件
    u32 alert_type = 0;

    // 1. 添加执行权限 (没有 X -> 有 X)
    if (!(old_prot & PROT_EXEC) && (prot & PROT_EXEC)) {
        if (prot & PROT_WRITE) {
            alert_type = ALERT_MPROT_W_ADD;  // 同时有 W+X
        } else {
            alert_type = ALERT_MPROT_X_ADD;  // 只添加 X
        }
    }
    // 2. 移除写权限但保持执行权限 (常见的 JIT 模式)
    else if ((old_prot & PROT_WRITE) && !(prot & PROT_WRITE) &&
             (prot & PROT_EXEC)) {
        alert_type = ALERT_MPROT_W_REM;
    }
    // 3. 直接变成 W+X
    else if (is_wx_violation(prot) && !is_wx_violation(old_prot)) {
        alert_type = ALERT_MPROT_W_ADD;
    }

    if (!alert_type)
        return 0;

    // 填充事件
    struct mprotect_event event = {};
    event.timestamp = bpf_ktime_get_ns();
    u64 pid_tgid = bpf_get_current_pid_tgid();
    event.pid = pid_tgid >> 32;
    event.tid = (u32)pid_tgid;
    event.uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    event.addr = BPF_CORE_READ(vma, vm_start);
    event.len = BPF_CORE_READ(vma, vm_end) - event.addr;
    event.prot = prot;
    event.old_prot = old_prot;
    event.alert_type = alert_type;

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));

    return 0;
}

// ============================================================================
// License
// ============================================================================

char LICENSE[] SEC("license") = "Dual BSD/GPL";
