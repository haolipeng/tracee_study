// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//
// Demo 6: cap_check - Capability Check Monitor
//
// 学习目标:
//   1. 理解 Linux Capabilities 机制
//   2. 追踪权限检查 (cap_capable)
//   3. 检测权限提升行为
//
// 参考 Tracee 代码:
//   - pkg/ebpf/c/tracee.bpf.c:2530-2549 (cap_capable)
//   - pkg/ebpf/c/common/capabilities.h

#include "common.h"

// ============================================================================
// Capability Definitions (from linux/capability.h)
// ============================================================================

#define CAP_CHOWN            0
#define CAP_DAC_OVERRIDE     1
#define CAP_DAC_READ_SEARCH  2
#define CAP_FOWNER           3
#define CAP_FSETID           4
#define CAP_KILL             5
#define CAP_SETGID           6
#define CAP_SETUID           7
#define CAP_SETPCAP          8
#define CAP_LINUX_IMMUTABLE  9
#define CAP_NET_BIND_SERVICE 10
#define CAP_NET_BROADCAST    11
#define CAP_NET_ADMIN        12
#define CAP_NET_RAW          13
#define CAP_IPC_LOCK         14
#define CAP_IPC_OWNER        15
#define CAP_SYS_MODULE       16
#define CAP_SYS_RAWIO        17
#define CAP_SYS_CHROOT       18
#define CAP_SYS_PTRACE       19
#define CAP_SYS_PACCT        20
#define CAP_SYS_ADMIN        21
#define CAP_SYS_BOOT         22
#define CAP_SYS_NICE         23
#define CAP_SYS_RESOURCE     24
#define CAP_SYS_TIME         25
#define CAP_SYS_TTY_CONFIG   26
#define CAP_MKNOD            27
#define CAP_LEASE            28
#define CAP_AUDIT_WRITE      29
#define CAP_AUDIT_CONTROL    30
#define CAP_SETFCAP          31
#define CAP_MAC_OVERRIDE     32
#define CAP_MAC_ADMIN        33
#define CAP_SYSLOG           34
#define CAP_WAKE_ALARM       35
#define CAP_BLOCK_SUSPEND    36
#define CAP_AUDIT_READ       37
#define CAP_PERFMON          38
#define CAP_BPF              39
#define CAP_CHECKPOINT_RESTORE 40

// cap_opt flags
#define CAP_OPT_NOAUDIT      0x01

// ============================================================================
// Event Structure
// ============================================================================

struct cap_event {
    u64 timestamp;
    u32 pid;
    u32 tid;
    u32 uid;
    char comm[TASK_COMM_LEN];

    int cap;                // 请求的 capability
    int cap_opt;            // 选项 (是否审计)
    int audit;              // 是否需要审计
};

// ============================================================================
// BPF Maps
// ============================================================================

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
} events SEC(".maps");

// 可选: 过滤特定 capability
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, int);       // capability number
    __type(value, u8);      // 1 = monitor this cap
} cap_filter SEC(".maps");

// ============================================================================
// Kprobe: cap_capable
// ============================================================================

// cap_capable 是内核检查 capability 的核心函数
// 函数签名: int cap_capable(const struct cred *cred,
//                           struct user_namespace *ns,
//                           int cap,
//                           unsigned int opts)
//
// 参考: Tracee pkg/ebpf/c/tracee.bpf.c:2530-2549
SEC("kprobe/cap_capable")
int BPF_KPROBE(trace_cap_capable, const struct cred *cred,
               struct user_namespace *ns, int cap, unsigned int opts)
{
    // 跳过无需审计的检查 (减少噪音)
    // CAP_OPT_NOAUDIT 表示这是一个探测性检查
    if (opts & CAP_OPT_NOAUDIT)
        return 0;

    struct cap_event event = {};

    // 基础信息
    event.timestamp = bpf_ktime_get_ns();
    u64 pid_tgid = bpf_get_current_pid_tgid();
    event.pid = pid_tgid >> 32;
    event.tid = (u32)pid_tgid;
    event.uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    // Capability 信息
    event.cap = cap;
    event.cap_opt = opts;
    event.audit = !(opts & CAP_OPT_NOAUDIT);

    // 可选: 检查是否在过滤列表中
    // u8 *filter = bpf_map_lookup_elem(&cap_filter, &cap);
    // if (!filter) return 0;

    // 发送事件
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));

    return 0;
}

// ============================================================================
// 高危 Capability 追踪 (示例: 只追踪特定 caps)
// ============================================================================

// 只追踪高危 capabilities
SEC("kprobe/cap_capable_dangerous")
int BPF_KPROBE(trace_dangerous_caps, const struct cred *cred,
               struct user_namespace *ns, int cap, unsigned int opts)
{
    // 只关注这些高危 capabilities
    switch (cap) {
        case CAP_SYS_ADMIN:
        case CAP_SYS_MODULE:
        case CAP_SYS_PTRACE:
        case CAP_SYS_RAWIO:
        case CAP_NET_ADMIN:
        case CAP_NET_RAW:
        case CAP_BPF:
            break;
        default:
            return 0;  // 忽略其他
    }

    struct cap_event event = {};
    event.timestamp = bpf_ktime_get_ns();
    u64 pid_tgid = bpf_get_current_pid_tgid();
    event.pid = pid_tgid >> 32;
    event.tid = (u32)pid_tgid;
    event.uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.cap = cap;
    event.cap_opt = opts;

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));

    return 0;
}

// ============================================================================
// License
// ============================================================================

char LICENSE[] SEC("license") = "Dual BSD/GPL";
