// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//
// Demo 5: connect_tracker - TCP Connection Tracker
//
// 学习目标:
//   1. 追踪 socket 连接操作
//   2. 理解 socket 数据结构
//   3. 处理 IPv4/IPv6 地址
//   4. 网络字节序转换
//
// 参考 Tracee 代码:
//   - pkg/ebpf/c/tracee.bpf.c:2696-2793 (security_socket_connect)
//   - pkg/ebpf/c/common/network.h

#include "common.h"

// ============================================================================
// Constants
// ============================================================================

// 地址族
#define AF_INET  2
#define AF_INET6 10

// Socket 类型
#define SOCK_STREAM 1   // TCP
#define SOCK_DGRAM  2   // UDP

// ============================================================================
// Event Structure
// ============================================================================

struct connect_event {
    u64 timestamp;
    u32 pid;
    u32 tid;
    u32 uid;
    char comm[TASK_COMM_LEN];

    u16 af;              // 地址族 (AF_INET / AF_INET6)
    u16 protocol;        // 协议 (TCP/UDP)
    u16 sport;           // 源端口
    u16 dport;           // 目标端口

    // IPv4/IPv6 地址 (使用 union 节省空间)
    union {
        u32 saddr_v4;
        u8  saddr_v6[16];
    };
    union {
        u32 daddr_v4;
        u8  daddr_v6[16];
    };
};

// ============================================================================
// BPF Maps
// ============================================================================

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
} events SEC(".maps");

// ============================================================================
// Helper Functions
// ============================================================================

// 获取 sockaddr 地址族
statfunc u16 get_sockaddr_family(struct sockaddr *addr)
{
    u16 family;
    bpf_probe_read_kernel(&family, sizeof(family), &addr->sa_family);
    return family;
}

// 填充 IPv4 连接信息
statfunc void fill_ipv4_info(struct connect_event *event, struct sockaddr_in *addr)
{
    event->af = AF_INET;
    bpf_probe_read_kernel(&event->daddr_v4, sizeof(event->daddr_v4), &addr->sin_addr);
    bpf_probe_read_kernel(&event->dport, sizeof(event->dport), &addr->sin_port);
    event->dport = bpf_ntohs(event->dport);
}

// 填充 IPv6 连接信息
statfunc void fill_ipv6_info(struct connect_event *event, struct sockaddr_in6 *addr)
{
    event->af = AF_INET6;
    bpf_probe_read_kernel(&event->daddr_v6, sizeof(event->daddr_v6), &addr->sin6_addr);
    bpf_probe_read_kernel(&event->dport, sizeof(event->dport), &addr->sin6_port);
    event->dport = bpf_ntohs(event->dport);
}

// ============================================================================
// Kprobe: security_socket_connect
// ============================================================================

// 追踪 connect() 系统调用
// 参考: Tracee pkg/ebpf/c/tracee.bpf.c:2696-2793
SEC("kprobe/security_socket_connect")
int BPF_KPROBE(trace_connect, struct socket *sock, struct sockaddr *address, int addrlen)
{
    struct connect_event event = {};

    // 基础信息
    event.timestamp = bpf_ktime_get_ns();
    u64 pid_tgid = bpf_get_current_pid_tgid();
    event.pid = pid_tgid >> 32;
    event.tid = (u32)pid_tgid;
    event.uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    // 获取 socket 类型
    u16 sock_type = BPF_CORE_READ(sock, type);

    // 只关注 TCP 和 UDP
    if (sock_type != SOCK_STREAM && sock_type != SOCK_DGRAM)
        return 0;

    event.protocol = sock_type;

    // 获取地址族
    u16 family = get_sockaddr_family(address);

    // 根据地址族处理
    switch (family) {
        case AF_INET:
            fill_ipv4_info(&event, (struct sockaddr_in *)address);
            break;
        case AF_INET6:
            fill_ipv6_info(&event, (struct sockaddr_in6 *)address);
            break;
        default:
            return 0;  // 忽略其他地址族
    }

    // 尝试获取本地地址和端口 (从 socket 结构)
    struct sock *sk = BPF_CORE_READ(sock, sk);
    if (sk) {
        // 对于 IPv4
        if (family == AF_INET) {
            event.saddr_v4 = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
            event.sport = BPF_CORE_READ(sk, __sk_common.skc_num);
        }
        // IPv6 源地址获取更复杂，这里简化处理
    }

    // 发送事件
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));

    return 0;
}

// ============================================================================
// Kprobe: security_socket_accept (接受连接)
// ============================================================================

SEC("kprobe/security_socket_accept")
int BPF_KPROBE(trace_accept, struct socket *sock, struct socket *newsock)
{
    struct connect_event event = {};

    event.timestamp = bpf_ktime_get_ns();
    u64 pid_tgid = bpf_get_current_pid_tgid();
    event.pid = pid_tgid >> 32;
    event.tid = (u32)pid_tgid;
    event.uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    // 从 socket 获取连接信息
    struct sock *sk = BPF_CORE_READ(sock, sk);
    if (!sk)
        return 0;

    u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);

    if (family == AF_INET) {
        event.af = AF_INET;
        event.saddr_v4 = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
        event.daddr_v4 = BPF_CORE_READ(sk, __sk_common.skc_daddr);
        event.sport = BPF_CORE_READ(sk, __sk_common.skc_num);
        event.dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
        event.protocol = SOCK_STREAM;  // accept 只用于 TCP

        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    }

    return 0;
}

// ============================================================================
// License
// ============================================================================

char LICENSE[] SEC("license") = "Dual BSD/GPL";
