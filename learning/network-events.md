# 网络事件捕获机制深度解析

> **学习时长**：3-4 天 | **难度**：⭐⭐⭐⭐ (高级)

## 学习目标

完成本章节学习后，你将能够：

1. 理解 Tracee 网络事件捕获的整体架构
2. 掌握 cgroup/skb eBPF 程序的挂载和工作原理
3. 理解 ingress/egress 数据包处理流程
4. 熟悉多层协议解析机制（L3/L4/L7）
5. 掌握 DNS 和 HTTP 协议的捕获与解析
6. 理解网络流追踪（net_flow_*）的实现
7. 了解 DNS 缓存的设计与应用
8. 能够扩展自定义网络协议解析

## 前置知识

- 熟悉 Linux 网络栈基础（TCP/IP 模型）
- 了解 eBPF cgroup 程序类型
- 完成第三阶段（eBPF 内核侧实现）的学习
- 熟悉 Go 语言和 gopacket 库基础

---

## 1. 网络事件捕获架构概览

### 1.1 整体架构图

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                            用户空间 (User Space)                              │
│  ┌─────────────────────────────────────────────────────────────────────────┐│
│  │                          Tracee Go Application                          ││
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌──────────────┐   ││
│  │  │ Net Capture │  │  Decoder    │  │  Derive     │  │  DNS Cache   │   ││
│  │  │  Handler    │  │  (gopacket) │  │  Engine     │  │  (LRU)       │   ││
│  │  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └──────┬───────┘   ││
│  │         │                │                │                 │           ││
│  └─────────┼────────────────┼────────────────┼─────────────────┼───────────┘│
│            │                │                │                 │            │
│   ┌────────▼────────────────▼────────────────▼─────────────────▼──────────┐ │
│   │                    Perf Event Buffer / Ring Buffer                     │ │
│   │  ┌──────────────────┐  ┌──────────────────┐                           │ │
│   │  │   events         │  │  net_cap_events  │                           │ │
│   │  │  (net_packet_*)  │  │  (pcap capture)  │                           │ │
│   │  └──────────────────┘  └──────────────────┘                           │ │
│   └───────────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────────┘
                                      ▲
                                      │ bpf_perf_event_output()
┌─────────────────────────────────────┼───────────────────────────────────────┐
│                            内核空间 (Kernel Space)                           │
│  ┌──────────────────────────────────┼──────────────────────────────────────┐│
│  │                    cgroup/skb eBPF Programs                              ││
│  │  ┌───────────────────────────────┴───────────────────────────────────┐  ││
│  │  │                     cgroup_skb_generic()                          │  ││
│  │  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐   │  ││
│  │  │  │  Ingress    │  │   Egress    │  │   Protocol Handlers     │   │  ││
│  │  │  │  Handler    │  │   Handler   │  │  proto_tcp/udp/icmp     │   │  ││
│  │  │  └──────┬──────┘  └──────┬──────┘  │  proto_dns/http         │   │  ││
│  │  │         │                │         └─────────────────────────┘   │  ││
│  │  └─────────┼────────────────┼───────────────────────────────────────┘  ││
│  │            │                │                                           ││
│  │  ┌─────────▼────────────────▼───────────────────────────────────────┐  ││
│  │  │                         BPF Maps                                  │  ││
│  │  │  ┌────────────┐  ┌────────────┐  ┌────────────┐  ┌────────────┐  │  ││
│  │  │  │ cgrpctxmap │  │ inodemap   │  │ netflowmap │  │  sockmap   │  │  ││
│  │  │  │  _in/_eg   │  │            │  │            │  │            │  │  ││
│  │  │  └────────────┘  └────────────┘  └────────────┘  └────────────┘  │  ││
│  │  └──────────────────────────────────────────────────────────────────┘  ││
│  └─────────────────────────────────────────────────────────────────────────┘│
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────────┐│
│  │                    kprobe: __cgroup_bpf_run_filter_skb                   ││
│  │  • 在 cgroup/skb 程序运行前准备上下文                                    ││
│  │  • 建立 socket inode -> task context 映射                               ││
│  │  • 解析 L3 头部，创建 indexer                                            ││
│  └─────────────────────────────────────────────────────────────────────────┘│
│                                      ▲                                       │
│                                      │                                       │
│  ┌───────────────────────────────────┴─────────────────────────────────────┐│
│  │                        Linux Network Stack                               ││
│  │                     (TCP/IP, Socket Layer, etc.)                        ││
│  └─────────────────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────────────────┘
```

### 1.2 设计理念

Tracee 的网络事件捕获基于以下核心设计理念：

1. **cgroup/skb 程序类型**：使用 `BPF_PROG_TYPE_CGROUP_SKB` 类型程序，挂载到 cgroup v2 根目录，可以捕获所有容器和主机的网络流量

2. **两阶段处理**：
   - **kprobe 阶段**：`__cgroup_bpf_run_filter_skb` 在 cgroup/skb 程序执行前准备上下文
   - **cgroup/skb 阶段**：解析数据包并提交事件

3. **协议分层解析**：按照 OSI 模型分层处理
   - L3：IPv4/IPv6
   - L4：TCP/UDP/ICMP
   - L7：DNS/HTTP

4. **事件派生机制**：内核只提交基础事件（base events），用户空间派生具体事件

---

## 2. cgroup/skb 程序详解

### 2.1 程序挂载

Tracee 使用 cgroup v2 的 skb 程序来捕获网络流量。程序定义在 `pkg/ebpf/c/tracee.bpf.c`:

```c
// 文件: pkg/ebpf/c/tracee.bpf.c:6745-6755

SEC("cgroup_skb/ingress")
int cgroup_skb_ingress(struct __sk_buff *ctx)
{
    return cgroup_skb_generic(ctx, &cgrpctxmap_in);
}

SEC("cgroup_skb/egress")
int cgroup_skb_egress(struct __sk_buff *ctx)
{
    return cgroup_skb_generic(ctx, &cgrpctxmap_eg);
}
```

**挂载过程**（Go 用户空间）:

```go
// 文件: pkg/ebpf/probes/cgroup.go:54-100

func (p *CgroupProbe) attach(module *bpf.Module, args ...interface{}) error {
    // 获取 cgroup v2 挂载点（通常是 /sys/fs/cgroup）
    cgroupV2 := cgroups.GetCgroup(cgroup.CgroupVersion2)
    cgroupV2MountPoint := cgroupV2.GetMountPoint()

    // 获取 eBPF 程序
    prog, err := module.GetProgram(p.programName)

    // 挂载到 cgroup 根目录
    // attachType: BPF_CGROUP_INET_INGRESS 或 BPF_CGROUP_INET_EGRESS
    link, err = prog.AttachCgroupLegacy(cgroupV2MountPoint, p.attachType)
}
```

### 2.2 ingress/egress 方向判断

```
                    ┌─────────────────┐
                    │   Network       │
                    │   Interface     │
                    └────────┬────────┘
                             │
         ┌───────────────────┼───────────────────┐
         │                   │                   │
         ▼                   │                   ▼
  ┌─────────────┐            │            ┌─────────────┐
  │  INGRESS    │            │            │   EGRESS    │
  │ (入站流量)   │            │            │ (出站流量)   │
  │             │            │            │             │
  │ packet_     │            │            │ packet_     │
  │ ingress     │            │            │ egress      │
  └──────┬──────┘            │            └──────┬──────┘
         │                   │                   │
         ▼                   │                   ▼
  ┌─────────────┐            │            ┌─────────────┐
  │ cgrpctxmap  │            │            │ cgrpctxmap  │
  │    _in      │            │            │    _eg      │
  └──────┬──────┘            │            └──────┬──────┘
         │                   │                   │
         └───────────────────┴───────────────────┘
                             │
                             ▼
                    ┌─────────────────┐
                    │   Application   │
                    │   (Socket)      │
                    └─────────────────┘
```

方向标志定义在 `pkg/ebpf/c/common/network.h`:

```c
// 文件: pkg/ebpf/c/common/network.h:221-222

// Packet Direction (ingress/egress) Flag
#define packet_ingress          (1 << 4)
#define packet_egress           (1 << 5)
```

### 2.3 kprobe 预处理阶段

在 cgroup/skb 程序运行前，kprobe 程序 `__cgroup_bpf_run_filter_skb` 会准备必要的上下文：

```c
// 文件: pkg/ebpf/c/tracee.bpf.c:6390-6614

SEC("kprobe/__cgroup_bpf_run_filter_skb")
int BPF_KPROBE(cgroup_bpf_run_filter_skb)
{
    // 1. 获取 socket 和 skb
    struct sock *sk = (void *) PT_REGS_PARM1(ctx);
    struct sk_buff *skb = (void *) PT_REGS_PARM2(ctx);
    int type = PT_REGS_PARM3(ctx);  // BPF_CGROUP_INET_INGRESS or EGRESS

    // 2. 判断方向，选择对应的 context map
    switch (type) {
        case BPF_CGROUP_INET_INGRESS:
            cgrpctxmap = &cgrpctxmap_in;
            packet_dir_flag = packet_ingress;
            break;
        case BPF_CGROUP_INET_EGRESS:
            cgrpctxmap = &cgrpctxmap_eg;
            packet_dir_flag = packet_egress;
            break;
    }

    // 3. 通过 socket inode 查找任务上下文
    u64 inode = BPF_CORE_READ(sk, sk_socket, file, f_inode, i_ino);
    netctx = bpf_map_lookup_elem(&inodemap, &inode);

    // 4. 如果是克隆的 socket（来自 accept()），从 sockmap 查找
    if (!netctx) {
        u64 skptr = (u64)(void *)sk;
        u64 *o = bpf_map_lookup_elem(&sockmap, &skptr);
        // ...
    }

    // 5. 准备网络事件上下文
    net_event_context_t neteventctx = {0};
    __builtin_memcpy(&eventctx->task, &netctx->taskctx, sizeof(task_context_t));
    eventctx->retval |= packet_dir_flag;  // 设置方向标志

    // 6. 解析 L3 头部，创建 indexer
    indexer_t indexer = {0};
    indexer.ts = BPF_CORE_READ(skb, tstamp);
    indexer.ip_csum = nethdrs->iphdrs.iphdr.check;
    indexer.src.in6_u.u6_addr32[0] = nethdrs->iphdrs.iphdr.saddr;
    indexer.dst.in6_u.u6_addr32[0] = nethdrs->iphdrs.iphdr.daddr;

    // 7. 保存到 context map，供后续 cgroup/skb 程序使用
    bpf_map_update_elem(cgrpctxmap, &indexer, &neteventctx, BPF_NOEXIST);
}
```

### 2.4 核心 Maps 说明

| Map 名称 | 类型 | Key | Value | 用途 |
|---------|------|-----|-------|------|
| `cgrpctxmap_in` | LRU_HASH | `indexer_t` | `net_event_context_t` | ingress 事件上下文 |
| `cgrpctxmap_eg` | LRU_HASH | `indexer_t` | `net_event_context_t` | egress 事件上下文 |
| `inodemap` | LRU_HASH | `u64 (inode)` | `net_task_context` | socket inode -> task 映射 |
| `sockmap` | LRU_HASH | `u64 (sock ptr)` | `u64 (old inode)` | 克隆 socket 映射 |
| `netflowmap` | LRU_HASH | `netflow_t` | `netflowvalue_t` | 网络流追踪 |
| `net_cap_events` | PERF_ARRAY | `u32` | `u32` | 网络捕获事件 buffer |

---

## 3. 数据包解析流程

### 3.1 通用处理函数

```c
// 文件: pkg/ebpf/c/tracee.bpf.c:6620-6743

statfunc u32 cgroup_skb_generic(struct __sk_buff *ctx, void *cgrpctxmap)
{
    // 1. 只处理 IPv4 和 IPv6
    switch (ctx->family) {
        case PF_INET:
        case PF_INET6:
            break;
        default:
            return 1;
    }

    // 2. 获取 full socket
    struct bpf_sock *sk = ctx->sk;
    sk = bpf_sk_fullsock(sk);

    // 3. 加载 L3 头部
    nethdrs hdrs = {0}, *nethdrs = &hdrs;
    switch (family) {
        case PF_INET:
            dest = &nethdrs->iphdrs.iphdr;
            size = bpf_core_type_size(struct iphdr);
            break;
        case PF_INET6:
            dest = &nethdrs->iphdrs.ipv6hdr;
            size = bpf_core_type_size(struct ipv6hdr);
            break;
    }
    bpf_skb_load_bytes_relative(ctx, 0, dest, size, BPF_HDR_START_NET);

    // 4. 构建 indexer，查找预先准备的事件上下文
    indexer_t indexer = {0};
    indexer.ts = ctx->tstamp;
    indexer.ip_csum = nethdrs->iphdrs.iphdr.check;
    // ...

    net_event_context_t *neteventctx;
    neteventctx = bpf_map_lookup_elem(cgrpctxmap, &indexer);
    if (!neteventctx)
        return 1;  // 未被追踪的任务

    // 5. 调用协议处理器
    u32 ret = CGROUP_SKB_HANDLE(proto);

    // 6. 清理 context map
    bpf_map_delete_elem(cgrpctxmap, &indexer);

    return ret;
}
```

### 3.2 协议处理链

```
                    ┌─────────────────┐
                    │ cgroup_skb_     │
                    │    generic()    │
                    └────────┬────────┘
                             │
                             ▼
                    ┌─────────────────┐
                    │ CGROUP_SKB_     │
                    │ HANDLE(proto)   │
                    └────────┬────────┘
                             │
              ┌──────────────┼──────────────┐
              │              │              │
              ▼              ▼              ▼
       ┌──────────┐   ┌──────────┐   ┌──────────┐
       │ proto_tcp│   │ proto_udp│   │proto_icmp│
       └────┬─────┘   └────┬─────┘   └──────────┘
            │              │
    ┌───────┼───────┐      │
    │       │       │      │
    ▼       ▼       ▼      ▼
┌──────┐ ┌──────┐ ┌──────────┐
│ DNS  │ │ HTTP │ │   DNS    │
│(TCP) │ │(TCP) │ │  (UDP)   │
└──────┘ └──────┘ └──────────┘
```

### 3.3 协议处理器宏定义

```c
// 文件: pkg/ebpf/c/tracee.bpf.c:5945-5962

// 定义协议处理函数签名
#define CGROUP_SKB_HANDLE_FUNCTION(name)                                       \
statfunc u32 cgroup_skb_handle_##name(                                         \
    struct __sk_buff *ctx,                                                     \
    net_event_context_t *neteventctx,                                          \
    nethdrs *nethdrs                                                           \
)

// 声明所有处理函数
CGROUP_SKB_HANDLE_FUNCTION(family);
CGROUP_SKB_HANDLE_FUNCTION(proto);
CGROUP_SKB_HANDLE_FUNCTION(proto_tcp);
CGROUP_SKB_HANDLE_FUNCTION(proto_tcp_dns);
CGROUP_SKB_HANDLE_FUNCTION(proto_tcp_http);
CGROUP_SKB_HANDLE_FUNCTION(proto_udp);
CGROUP_SKB_HANDLE_FUNCTION(proto_udp_dns);
CGROUP_SKB_HANDLE_FUNCTION(proto_icmp);
CGROUP_SKB_HANDLE_FUNCTION(proto_icmpv6);

// 调用处理函数的宏
#define CGROUP_SKB_HANDLE(name) cgroup_skb_handle_##name(ctx, neteventctx, nethdrs);
```

---

## 4. 协议层解析详解

### 4.1 L3 层解析（IP/IPv6）

```c
// 文件: pkg/ebpf/c/tracee.bpf.c:6765-6892

CGROUP_SKB_HANDLE_FUNCTION(proto)
{
    u32 prev_hdr_size = neteventctx->md.header_size;
    u8 next_proto = 0;

    switch (ctx->family) {
        case PF_INET:
            if (nethdrs->iphdrs.iphdr.version != 4)
                return 1;

            next_proto = nethdrs->iphdrs.iphdr.protocol;

            // 根据下一层协议设置目标缓冲区
            switch (next_proto) {
                case IPPROTO_TCP:
                    dest = &nethdrs->protohdrs.tcphdr;
                    size = bpf_core_type_size(struct tcphdr);
                    break;
                case IPPROTO_UDP:
                    dest = &nethdrs->protohdrs.udphdr;
                    size = bpf_core_type_size(struct udphdr);
                    break;
                case IPPROTO_ICMP:
                    dest = &nethdrs->protohdrs.icmphdr;
                    break;
            }

            // 更新 flow 信息
            neteventctx->md.flow.src.u6_addr32[0] = nethdrs->iphdrs.iphdr.saddr;
            neteventctx->md.flow.dst.u6_addr32[0] = nethdrs->iphdrs.iphdr.daddr;
            break;

        case PF_INET6:
            // IPv6 处理类似...
            break;
    }

    // 提交原始包和 IP 事件（如果策略要求）
    if (should_submit_net_event(neteventctx, SUB_NET_PACKET_RAW))
        cgroup_skb_submit_event(ctx, neteventctx, NET_PACKET_RAW, FULL);

    if (should_submit_net_event(neteventctx, SUB_NET_PACKET_IP))
        cgroup_skb_submit_event(ctx, neteventctx, NET_PACKET_IP, HEADERS);

    // 加载 L4 头部
    bpf_skb_load_bytes_relative(ctx, prev_hdr_size, dest, size, BPF_HDR_START_NET);

    // 调用下一层处理器
    switch (next_proto) {
        case IPPROTO_TCP:
            return CGROUP_SKB_HANDLE(proto_tcp);
        case IPPROTO_UDP:
            return CGROUP_SKB_HANDLE(proto_udp);
        case IPPROTO_ICMP:
            return CGROUP_SKB_HANDLE(proto_icmp);
    }
}
```

### 4.2 L4 层解析（TCP/UDP）

#### TCP 处理

```c
// 文件: pkg/ebpf/c/tracee.bpf.c:6933-7003

CGROUP_SKB_HANDLE_FUNCTION(proto_tcp)
{
    // 1. 处理 TCP 动态头部长度（Data Offset）
    if (nethdrs->protohdrs.tcphdr.doff > 5) {
        u32 doff = nethdrs->protohdrs.tcphdr.doff * (32 / 8);
        neteventctx->md.header_size -= bpf_core_type_size(struct tcphdr);
        neteventctx->md.header_size += doff;
    }

    // 2. 提取端口信息
    u16 srcport = bpf_ntohs(nethdrs->protohdrs.tcphdr.source);
    u16 dstport = bpf_ntohs(nethdrs->protohdrs.tcphdr.dest);
    neteventctx->md.flow.srcport = srcport;
    neteventctx->md.flow.dstport = dstport;

    // 3. 检测 TCP 流事件
    bool is_syn = nethdrs->protohdrs.tcphdr.syn;
    bool is_ack = nethdrs->protohdrs.tcphdr.ack;
    bool is_fin = nethdrs->protohdrs.tcphdr.fin;
    bool is_rst = nethdrs->protohdrs.tcphdr.rst;

    // SYN+ACK 表示连接开始
    if ((is_syn & is_ack) && should_submit_flow_event(neteventctx))
        cgroup_skb_submit_flow(ctx, neteventctx, NET_FLOW_BASE, HEADERS, flow_tcp_begin);

    // FIN 或 RST 表示连接结束
    if ((is_fin || is_rst) && should_submit_flow_event(neteventctx))
        cgroup_skb_submit_flow(ctx, neteventctx, NET_FLOW_BASE, HEADERS, flow_tcp_end);

    // 4. 提交 TCP 事件
    if (should_submit_net_event(neteventctx, SUB_NET_PACKET_TCP))
        cgroup_skb_submit_event(ctx, neteventctx, NET_PACKET_TCP, HEADERS);

    // 5. 检测 L7 协议
    // 通过端口猜测 DNS
    switch (srcport < dstport ? srcport : dstport) {
        case TCP_PORT_DNS:  // 53
            return CGROUP_SKB_HANDLE(proto_tcp_dns);
    }

    // 通过内容分析检测 HTTP
    int http_proto = net_l7_is_http(ctx, neteventctx->md.header_size);
    if (http_proto) {
        neteventctx->eventctx.retval |= http_proto;
        return CGROUP_SKB_HANDLE(proto_tcp_http);
    }
}
```

#### UDP 处理

```c
// 文件: pkg/ebpf/c/tracee.bpf.c:7005-7043

CGROUP_SKB_HANDLE_FUNCTION(proto_udp)
{
    // 提交 UDP 事件
    if (should_submit_net_event(neteventctx, SUB_NET_PACKET_UDP))
        cgroup_skb_submit_event(ctx, neteventctx, NET_PACKET_UDP, HEADERS);

    // 通过端口猜测 L7 协议
    u16 source = bpf_ntohs(nethdrs->protohdrs.udphdr.source);
    u16 dest = bpf_ntohs(nethdrs->protohdrs.udphdr.dest);

    switch (source < dest ? source : dest) {
        case UDP_PORT_DNS:  // 53
            return CGROUP_SKB_HANDLE(proto_udp_dns);
    }
}
```

### 4.3 L7 层解析（DNS/HTTP）

#### DNS 检测

DNS 通过端口号（53）进行检测：

```c
// 文件: pkg/ebpf/c/common/network.h:235-237

#define UDP_PORT_DNS 53
#define TCP_PORT_DNS 53
```

```c
// 文件: pkg/ebpf/c/tracee.bpf.c:7098-7113

CGROUP_SKB_HANDLE_FUNCTION(proto_udp_dns)
{
    // 提交 DNS 事件（完整包）
    if (should_submit_net_event(neteventctx, SUB_NET_PACKET_DNS))
        cgroup_skb_submit_event(ctx, neteventctx, NET_PACKET_DNS, FULL);

    // 捕获用于 pcap
    if (should_capture_net_event(neteventctx, SUB_NET_PACKET_DNS)) {
        neteventctx->md.header_size = ctx->len;  // 完整 DNS 数据
        cgroup_skb_capture();
    }

    return 1;
}
```

#### HTTP 检测

HTTP 通过分析 payload 内容进行检测：

```c
// 文件: pkg/ebpf/c/tracee.bpf.c:6902-6927

statfunc int net_l7_is_http(struct __sk_buff *skb, u32 l7_off)
{
    char http_min_str[http_min_len];  // http_min_len = 7
    __builtin_memset((void *)&http_min_str, 0, sizeof(char) * http_min_len);

    // 加载 L7 层前 7 个字节
    if (bpf_skb_load_bytes(skb, l7_off, http_min_str, http_min_len) < 0) {
        return 0;
    }

    // 检测 HTTP 响应
    if (strncmp("HTTP/", http_min_str, 5) == 0) {
        return proto_http_resp;
    }

    // 检测 HTTP 请求
    if (strncmp("GET ", http_min_str, 4) == 0 ||
        strncmp("POST ", http_min_str, 5) == 0 ||
        strncmp("PUT ", http_min_str, 4) == 0 ||
        strncmp("DELETE ", http_min_str, 7) == 0 ||
        strncmp("HEAD ", http_min_str, 5) == 0) {
        return proto_http_req;
    }

    return 0;
}
```

---

## 5. 网络流追踪（net_flow_*）

### 5.1 流追踪数据结构

```c
// 文件: pkg/ebpf/c/common/network.h:23-43

typedef struct netflow {
    u32 host_pid;       // 主机 PID
    u8 proto;           // 协议（TCP/UDP）
    union {
        __u8 u6_addr8[16];
        __be16 u6_addr16[8];
        __be32 u6_addr32[4];
    } src, dst;         // 源/目标地址（支持 IPv4/IPv6）
    u16 srcport;        // 源端口
    u16 dstport;        // 目标端口
} __attribute__((__packed__)) netflow_t;

typedef struct netflowvalue {
    u8 direction;       // 0=unknown, 1=incoming, 2=outgoing
    u64 last_update;    // 最后更新时间
} __attribute__((__packed__)) netflowvalue_t;
```

### 5.2 TCP 流开始检测

```c
// 文件: pkg/ebpf/c/tracee.bpf.c:6040-6057

case flow_tcp_begin:
    // SYN+ACK 方向决定连接方向
    // Ingress: 远端发送 SYN+ACK -> 本机是发起方（outgoing）
    if (retval_hasflag(packet_ingress))
        netflowvalue.direction = flow_outgoing;

    // Egress: 本机发送 SYN+ACK -> 远端是发起方（incoming）
    if (retval_hasflag(packet_egress))
        netflowvalue.direction = flow_incoming;

    // 反转 src/dst：flowmap 的 src 始终是发起方
    neteventctx->md.flow = invert_netflow(neteventctx->md.flow);

    // 更新流追踪 map
    bpf_map_update_elem(&netflowmap, &neteventctx->md.flow, &netflowvalue, BPF_NOEXIST);
    break;
```

### 5.3 TCP 流结束检测

```c
// 文件: pkg/ebpf/c/tracee.bpf.c:6059-6099

case flow_tcp_end:
    // FIN 可能由任一方发送，需要启发式判断

    // 尝试 1：使用当前 src/dst 查找
    netflowvalptr = bpf_map_lookup_elem(&netflowmap, &neteventctx->md.flow);

    if (!netflowvalptr) {
        // 尝试 2：反转 src/dst 后查找
        neteventctx->md.flow = invert_netflow(neteventctx->md.flow);
        netflowvalptr = bpf_map_lookup_elem(&netflowmap, &neteventctx->md.flow);

        if (!netflowvalptr)
            return 0;  // 首个 FIN 处理后已删除流

        is_initiator = 0;  // 当前包的 dst 是发起方
    } else {
        is_initiator = 1;  // 当前包的 src 是发起方
    }
    break;
```

### 5.4 用户空间派生

```go
// 文件: pkg/events/derive/net_flow.go:15-80

func NetFlowTCPBegin(cache *dnscache.DNSCache) DeriveFunction {
    return deriveSingleEvent(events.NetFlowTCPBegin,
        func(event *trace.Event) ([]interface{}, error) {
            tcpBegin := event.ReturnValue&flowTCPBegin == flowTCPBegin
            ingress := event.ReturnValue&packetIngress == packetIngress
            egress := event.ReturnValue&packetEgress == packetEgress

            if !tcpBegin {
                return nil, nil
            }

            packet, err := createPacketFromEvent(event)
            srcIP, dstIP, _ := getLayer3SrcDstFromPacket(packet)
            srcPort, dstPort, _ := getLayer4SrcPortDstPortFromPacket(packet)

            connectionDirection := ""
            switch {
            case ingress:
                connectionDirection = directionOutgoing  // SYN+ACK 入站 -> 连接出站
            case egress:
                connectionDirection = directionIncoming  // SYN+ACK 出站 -> 连接入站
            }

            // SYN+ACK 包需要交换 src/dst 得到连接方向
            srcIP, dstIP, srcPort, dstPort = swapSrcDst(srcIP, dstIP, srcPort, dstPort)

            // 从 DNS 缓存获取域名
            srcDomains := getDomainsFromCache(srcIP, cache)
            dstDomains := getDomainsFromCache(dstIP, cache)

            return []interface{}{
                connectionDirection,
                srcIP, dstIP,
                srcPort, dstPort,
                srcDomains, dstDomains,
            }, nil
        },
    )
}
```

---

## 6. DNS 缓存实现

### 6.1 缓存架构

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          DNS Cache                                       │
│                                                                          │
│  ┌────────────────────────────────────────────────────────────────────┐ │
│  │                    queryRoots (LRU Cache)                          │ │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐                         │ │
│  │  │example   │  │google    │  │github    │  ...                    │ │
│  │  │.com      │  │.com      │  │.com      │                         │ │
│  │  └────┬─────┘  └──────────┘  └──────────┘                         │ │
│  │       │                                                             │ │
│  │       ▼                                                             │ │
│  │  ┌──────────┐                                                       │ │
│  │  │ CNAME:   │                                                       │ │
│  │  │www.exam..│                                                       │ │
│  │  └────┬─────┘                                                       │ │
│  │       │                                                             │ │
│  │       ├─────────────────┐                                           │ │
│  │       ▼                 ▼                                           │ │
│  │  ┌──────────┐     ┌──────────┐                                     │ │
│  │  │ A:       │     │ A:       │                                     │ │
│  │  │93.184.2..│     │93.184.2..│                                     │ │
│  │  └──────────┘     └──────────┘                                     │ │
│  └────────────────────────────────────────────────────────────────────┘ │
│                                                                          │
│  ┌────────────────────────────────────────────────────────────────────┐ │
│  │                    queryIndices (Map)                               │ │
│  │  "example.com"     -> dnsNode*                                     │ │
│  │  "www.example.com" -> dnsNode*                                     │ │
│  │  "93.184.216.34"   -> dnsNode*                                     │ │
│  └────────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────┘
```

### 6.2 核心数据结构

```go
// 文件: pkg/dnscache/dnscache.go:24-46

type DNSCache struct {
    queryRoots   *lru.Cache[string, *dnsNode]  // LRU 缓存根节点
    queryIndices map[string]*dnsNode           // 全局索引
    lock         *sync.RWMutex                 // 读写锁
}

// 文件: pkg/dnscache/node.go:18-24

type dnsNode struct {
    value        string                         // DNS 名称或 IP 地址
    nodeType     nodeType                       // DNS 或 IP
    expiredAfter time.Time                      // TTL 过期时间
    parents      *set.Set[*dnsNode, string]     // 父节点（反向引用）
    next         *set.Set[*dnsNode, string]     // 子节点
}
```

### 6.3 DNS 响应添加

```go
// 文件: pkg/dnscache/dnscache.go:48-80

func (nc *DNSCache) Add(event *trace.Event) error {
    // 1. 解析 DNS 参数
    dns, err := parse.ArgVal[trace.ProtoDNS](event.Args, "proto_dns")

    // 2. 只处理 DNS 响应（QR=1）
    if dns.QR != 1 || len(dns.Answers) < 1 {
        return nil
    }

    nc.lock.Lock()
    defer nc.lock.Unlock()

    question := dns.Questions[0].Name
    questionNode, ok := nc.queryIndices[question]

    // 3. 如果问题未索引，创建根节点
    if !ok {
        nc.addRootNode(&dns, eventUnixTimestamp)
    } else {
        // 4. 否则添加子节点（CNAME, A, AAAA 等）
        nc.addChildNodes(dns.Answers, questionNode, eventUnixTimestamp)
    }
    return nil
}
```

### 6.4 DNS 查询

```go
// 文件: pkg/dnscache/dnscache.go:82-119

func (nc *DNSCache) Get(key string) (cacheQuery, error) {
    nc.lock.RLock()
    defer nc.lock.RUnlock()

    // 处理反向查询后缀
    key = strings.TrimSuffix(key, reverseQueryIPv4Suffix)  // .in-addr.arpa
    key = strings.TrimSuffix(key, reverseQueryIPv6Suffix)  // .ip6.arpa

    // 查找节点
    node, ok := nc.queryIndices[key]
    if !ok {
        return cacheQuery{}, ErrDNSRecordNotFound
    }

    // 检查是否过期
    if time.Now().After(node.expiredAfter) {
        return cacheQuery{}, ErrDNSRecordExpired
    }

    queryResult := cacheQuery{
        dnsResults: []string{},
        ipResults:  []string{},
    }

    // 收集当前节点
    nc.addSingleNodeToQueryResult(node, &queryResult, false)
    // 收集子节点
    nc.addNodeChildrenToQueryResult(node, &queryResult, time.Now())
    // 收集父节点
    nc.addNodeParentsToQueryResult(node, &queryResult, time.Now())

    return queryResult, nil
}
```

### 6.5 DataSource 接口

DNS 缓存实现了 DataSource 接口，供签名引擎使用：

```go
// 文件: pkg/dnscache/datasource.go:10-53

type DNSDatasource struct {
    dns *DNSCache
}

func (ctx DNSDatasource) Get(key interface{}) (map[string]interface{}, error) {
    keyString, ok := key.(string)
    if !ok {
        return nil, detect.ErrKeyNotSupported
    }

    query, err := ctx.dns.Get(keyString)
    if errors.Is(err, ErrDNSRecordNotFound) {
        return nil, detect.ErrDataNotFound
    }

    return map[string]interface{}{
        "ip_addresses": query.ipResults,
        "dns_queries":  query.dnsResults,
        "dns_root":     query.dnsResults[0],  // 原始查询
    }, nil
}
```

---

## 7. 网络事件列表

### 7.1 基础事件（eBPF 直接提交）

| 事件 ID | 事件名称 | 层级 | 说明 |
|---------|---------|------|------|
| 700 | `net_packet_base` | - | 网络包基础事件（内部使用） |
| 701 | `net_packet_raw` | L2 | 原始网络包 |
| 702 | `net_packet_ip_base` | L3 | IP 包基础事件 |
| 703 | `net_packet_tcp_base` | L4 | TCP 包基础事件 |
| 704 | `net_packet_udp_base` | L4 | UDP 包基础事件 |
| 705 | `net_packet_icmp_base` | L3/L4 | ICMP 包基础事件 |
| 706 | `net_packet_icmpv6_base` | L3/L4 | ICMPv6 包基础事件 |
| 707 | `net_packet_dns_base` | L7 | DNS 包基础事件 |
| 708 | `net_packet_http_base` | L7 | HTTP 包基础事件 |
| 709 | `net_packet_capture` | - | 网络捕获事件（用于 pcap） |
| 710 | `net_packet_flow_base` | - | 网络流基础事件 |

### 7.2 派生事件（用户空间派生）

| 事件 ID | 事件名称 | 说明 |
|---------|---------|------|
| 2000 | `net_packet_ipv4` | IPv4 包事件 |
| 2001 | `net_packet_ipv6` | IPv6 包事件 |
| 2002 | `net_packet_tcp` | TCP 包事件 |
| 2003 | `net_packet_udp` | UDP 包事件 |
| 2004 | `net_packet_icmp` | ICMP 包事件 |
| 2005 | `net_packet_icmpv6` | ICMPv6 包事件 |
| 2006 | `net_packet_dns` | DNS 包事件（推荐用于签名） |
| 2007 | `net_packet_dns_request` | DNS 请求事件 |
| 2008 | `net_packet_dns_response` | DNS 响应事件 |
| 2009 | `net_packet_http` | HTTP 包事件（推荐用于签名） |
| 2010 | `net_packet_http_request` | HTTP 请求事件 |
| 2011 | `net_packet_http_response` | HTTP 响应事件 |
| 2013 | `net_flow_tcp_begin` | TCP 连接开始 |
| 2014 | `net_flow_tcp_end` | TCP 连接结束 |

### 7.3 事件包含位标志（retval 编码）

```c
// 文件: pkg/ebpf/c/common/network.h:214-228

// L3 协议标志
#define family_ipv4             (1 << 0)  // 0x01
#define family_ipv6             (1 << 1)  // 0x02

// HTTP 方向标志
#define proto_http_req          (1 << 2)  // 0x04
#define proto_http_resp         (1 << 3)  // 0x08

// 包方向标志
#define packet_ingress          (1 << 4)  // 0x10
#define packet_egress           (1 << 5)  // 0x20

// TCP 流标志
#define flow_tcp_begin          (1 << 6)  // 0x40
#define flow_tcp_end            (1 << 7)  // 0x80
#define flow_udp_begin          (1 << 8)  // 0x100
#define flow_udp_end            (1 << 9)  // 0x200
#define flow_src_initiator      (1 << 10) // 0x400
```

---

## 8. 网络数据包捕获（PCAP）

### 8.1 捕获流程

```go
// 文件: pkg/ebpf/net_capture.go:32-50

func (t *Tracee) handleNetCaptureEvents(ctx context.Context) {
    // 使用独立的 perf buffer：net_cap_events
    eventsChan, errChan := t.decodeEvents(ctx, t.netCapChannel)

    // 处理网络捕获事件
    errChan = t.processNetCapEvents(ctx, eventsChan)

    // 等待管道完成
    t.WaitForPipeline(errChanList...)
}
```

### 8.2 包处理与写入

```go
// 文件: pkg/ebpf/net_capture.go:86-328

func (t *Tracee) processNetCapEvent(event *trace.Event) {
    switch eventId {
    case events.NetPacketCapture:
        // 1. 提取 payload
        payloadArg := events.GetArg(event.Args, "payload")
        payloadLayer3, _ := payloadArg.Value.([]byte)

        // 2. 判断 L3 协议类型
        if event.ReturnValue&familyIpv4 == familyIpv4 {
            layerType = layers.LayerTypeIPv4
        } else if event.ReturnValue&familyIPv6 == familyIPv6 {
            layerType = layers.LayerTypeIPv6
        }

        // 3. 添加伪造的 L2 头（BSD loopback encapsulation）
        layer2Slice := make([]byte, 4)
        payloadLayer2 = append(layer2Slice[:], payloadLayer3...)

        // 4. 解析包
        packet := gopacket.NewPacket(payloadLayer2[4:], layerType, gopacket.Default)

        // 5. 修正 IP 头部长度字段（针对截断捕获）
        switch v := layer3.(type) {
        case (*layers.IPv4):
            binary.BigEndian.PutUint32(payloadLayer2, 2)  // BSD IPv4
            // 调整 length 字段...
        case (*layers.IPv6):
            binary.BigEndian.PutUint32(payloadLayer2, 28) // BSD IPv6
            // 调整 length 字段...
        }

        // 6. 写入 pcap 文件
        err := t.netCapturePcap.Write(event, payloadLayer2)
    }
}
```

---

## 9. 与内核网络栈的交互

### 9.1 挂载点位置

```
           ┌─────────────────────────────────────────────────────────────┐
           │                    Application                              │
           │                   (send/recv)                               │
           └──────────────────────────┬──────────────────────────────────┘
                                      │
           ┌──────────────────────────▼──────────────────────────────────┐
           │                    Socket Layer                             │
           │  security_socket_sendmsg() ◄─── kprobe: 捕获发送消息        │
           │  security_socket_recvmsg() ◄─── kprobe: 捕获接收消息        │
           │  security_socket_connect() ◄─── kprobe: 捕获连接            │
           └──────────────────────────┬──────────────────────────────────┘
                                      │
           ┌──────────────────────────▼──────────────────────────────────┐
           │              __cgroup_bpf_run_filter_skb                    │
           │  ┌─────────────────────────────────────────────────────────┐│
           │  │ kprobe: 准备网络事件上下文                              ││
           │  │ • 获取 socket inode                                     ││
           │  │ • 查找任务上下文（inodemap/sockmap）                    ││
           │  │ • 解析 L3 头部                                          ││
           │  │ • 设置 cgrpctxmap                                       ││
           │  └─────────────────────────────────────────────────────────┘│
           └──────────────────────────┬──────────────────────────────────┘
                                      │
           ┌──────────────────────────▼──────────────────────────────────┐
           │                    cgroup/skb                               │
           │  ┌─────────────────────────────────────────────────────────┐│
           │  │ • cgroup_skb/ingress - 入站流量处理                     ││
           │  │ • cgroup_skb/egress  - 出站流量处理                     ││
           │  │ • 协议解析链: proto -> proto_tcp/udp -> proto_dns/http  ││
           │  │ • 提交事件到 perf buffer                                ││
           │  └─────────────────────────────────────────────────────────┘│
           └──────────────────────────┬──────────────────────────────────┘
                                      │
           ┌──────────────────────────▼──────────────────────────────────┐
           │                    TCP/IP Stack                             │
           │                  (routing, etc.)                            │
           └──────────────────────────┬──────────────────────────────────┘
                                      │
           ┌──────────────────────────▼──────────────────────────────────┐
           │                  Network Interface                          │
           └─────────────────────────────────────────────────────────────┘
```

### 9.2 Socket 到 Task 的映射

Tracee 需要将网络事件关联到发起进程。这通过以下机制实现：

1. **`security_socket_sendmsg/recvmsg` kprobe**：
   - 捕获 socket 操作
   - 获取 socket 的 inode
   - 保存 inode -> task context 映射到 `inodemap`

2. **`security_sk_clone` kprobe**：
   - 处理 accept() 创建的新 socket
   - 新 socket 没有关联的 inode
   - 保存新 socket 指针 -> 旧 inode 映射到 `sockmap`

3. **cgroup/skb 查找**：
   - 首先尝试从 socket 获取 inode
   - 使用 inode 查找 `inodemap`
   - 如果失败，使用 socket 指针查找 `sockmap`

```c
// 文件: pkg/ebpf/c/tracee.bpf.c:6241-6331

SEC("kprobe/security_sk_clone")
int BPF_KPROBE(trace_security_sk_clone)
{
    struct sock *osock = (struct sock *) PT_REGS_PARM1(ctx);
    struct sock *nsock = (struct sock *) PT_REGS_PARM2(ctx);

    // 获取旧 socket 的 inode
    u64 oinode = BPF_CORE_READ(osock, sk_socket, file, f_inode, i_ino);

    // 保存新 socket 指针 -> 旧 inode 的映射
    u64 sockptr = (u64)(void *)nsock;
    bpf_map_update_elem(&sockmap, &sockptr, &oinode, BPF_NOEXIST);
}
```

---

## 10. 动手练习

### 练习 1：捕获 DNS 查询

**目标**：使用 Tracee 捕获并分析 DNS 查询

```bash
# 1. 启动 Tracee 监控 DNS 事件
sudo ./dist/tracee -e net_packet_dns

# 2. 在另一个终端执行 DNS 查询
dig google.com
nslookup github.com
```

**预期输出**：
```json
{
  "eventName": "net_packet_dns",
  "args": {
    "src": "192.168.1.100",
    "dst": "8.8.8.8",
    "src_port": 54321,
    "dst_port": 53,
    "proto_dns": {
      "questions": [{"name": "google.com", "type": "A"}],
      "answers": [{"name": "google.com", "type": "A", "IP": "142.250.x.x"}]
    }
  }
}
```

### 练习 2：追踪 TCP 连接

**目标**：追踪 TCP 连接的建立和关闭

```bash
# 1. 启动 Tracee 监控 TCP 流事件
sudo ./dist/tracee -e net_flow_tcp_begin,net_flow_tcp_end

# 2. 执行网络请求
curl https://google.com
wget https://github.com
```

**分析**：
- `net_flow_tcp_begin`：观察连接方向（incoming/outgoing）
- `net_flow_tcp_end`：观察连接持续时间

### 练习 3：分析 HTTP 请求

**目标**：捕获 HTTP 请求和响应

```bash
# 1. 启动 Tracee
sudo ./dist/tracee -e net_packet_http_request,net_packet_http_response

# 2. 发起 HTTP 请求（注意：HTTPS 无法解密）
curl http://httpbin.org/get
curl -X POST http://httpbin.org/post -d "test=data"
```

### 练习 4：网络包捕获到 PCAP

**目标**：将网络流量捕获到 pcap 文件

```bash
# 1. 启动 Tracee 并捕获到 pcap
sudo ./dist/tracee --capture net --output option:net-capture-dir=/tmp/pcap

# 2. 生成一些流量
ping -c 3 8.8.8.8
curl http://example.com

# 3. 分析捕获的 pcap
tcpdump -r /tmp/pcap/*.pcap
wireshark /tmp/pcap/*.pcap
```

### 练习 5：编写 DNS 隧道检测签名

**目标**：检测可疑的 DNS 隧道活动

创建签名文件 `dns_tunnel_detector.go`:

```go
package main

import (
    "strings"

    "github.com/aquasecurity/tracee/signatures/helpers"
    "github.com/aquasecurity/tracee/types/detect"
    "github.com/aquasecurity/tracee/types/trace"
)

type DNSTunnelDetector struct {
    cb detect.SignatureHandler
}

func (sig *DNSTunnelDetector) Init(ctx detect.SignatureContext) error {
    sig.cb = ctx.Callback
    return nil
}

func (sig *DNSTunnelDetector) GetMetadata() (detect.SignatureMetadata, error) {
    return detect.SignatureMetadata{
        ID:          "DNS_TUNNEL",
        Name:        "DNS Tunnel Detection",
        Description: "Detects potential DNS tunneling activity",
    }, nil
}

func (sig *DNSTunnelDetector) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
    return []detect.SignatureEventSelector{
        {Source: "tracee", Name: "net_packet_dns"},
    }, nil
}

func (sig *DNSTunnelDetector) OnEvent(event *trace.Event) error {
    dns, err := helpers.GetTraceeProtoArgByName[trace.ProtoDNS](event, "proto_dns")
    if err != nil {
        return nil
    }

    for _, q := range dns.Questions {
        // 检测特征：
        // 1. 查询名过长（可能包含编码数据）
        // 2. 包含多个子域（数据分片）
        // 3. 非常见查询类型（TXT, NULL）

        if len(q.Name) > 100 {
            sig.cb(detect.Finding{
                SigMetadata: sig.GetMetadata(),
                Event:       *event,
                Data: map[string]interface{}{
                    "query_name":   q.Name,
                    "query_length": len(q.Name),
                    "reason":       "Unusually long DNS query",
                },
            })
        }

        subdomains := strings.Split(q.Name, ".")
        if len(subdomains) > 6 {
            sig.cb(detect.Finding{
                SigMetadata: sig.GetMetadata(),
                Event:       *event,
                Data: map[string]interface{}{
                    "query_name": q.Name,
                    "subdomain_count": len(subdomains),
                    "reason": "Excessive subdomain depth",
                },
            })
        }
    }

    return nil
}

func (sig *DNSTunnelDetector) OnSignal(s detect.Signal) error {
    return nil
}

func (sig *DNSTunnelDetector) Close() {}
```

---

## 11. 核心代码走读

### 11.1 推荐阅读顺序

| 优先级 | 文件路径 | 说明 | 建议时间 |
|--------|---------|------|---------|
| 1 | `pkg/ebpf/c/common/network.h` | 网络数据结构定义 | 30min |
| 2 | `pkg/ebpf/c/tracee.bpf.c:6390-6755` | cgroup/skb 程序实现 | 2h |
| 3 | `pkg/ebpf/c/tracee.bpf.c:5940-6140` | 事件提交函数 | 1h |
| 4 | `pkg/ebpf/c/tracee.bpf.c:6765-7130` | 协议处理器实现 | 1.5h |
| 5 | `pkg/events/derive/net_packet.go` | 网络事件派生 | 1h |
| 6 | `pkg/events/derive/net_packet_helpers.go` | 包解析辅助函数 | 1h |
| 7 | `pkg/events/derive/net_flow.go` | 流事件派生 | 45min |
| 8 | `pkg/dnscache/dnscache.go` | DNS 缓存核心 | 45min |
| 9 | `pkg/ebpf/net_capture.go` | 网络捕获处理 | 30min |
| 10 | `pkg/ebpf/probes/cgroup.go` | cgroup 程序挂载 | 20min |

### 11.2 关键函数索引

**eBPF 内核侧**：

| 函数 | 位置 | 功能 |
|-----|------|------|
| `cgroup_bpf_run_filter_skb` | tracee.bpf.c:6390 | kprobe 预处理 |
| `cgroup_skb_generic` | tracee.bpf.c:6620 | 通用 skb 处理 |
| `cgroup_skb_handle_proto` | tracee.bpf.c:6765 | L3 协议处理 |
| `cgroup_skb_handle_proto_tcp` | tracee.bpf.c:6933 | TCP 处理 |
| `cgroup_skb_handle_proto_udp` | tracee.bpf.c:7005 | UDP 处理 |
| `net_l7_is_http` | tracee.bpf.c:6902 | HTTP 检测 |
| `cgroup_skb_submit` | tracee.bpf.c:5969 | 事件提交 |
| `cgroup_skb_submit_flow` | tracee.bpf.c:6022 | 流事件提交 |
| `should_submit_net_event` | tracee.bpf.c:5882 | 事件过滤判断 |

**Go 用户侧**：

| 函数 | 位置 | 功能 |
|-----|------|------|
| `NetPacketDNS()` | net_packet.go:192 | DNS 事件派生 |
| `NetPacketHTTP()` | net_packet.go:334 | HTTP 事件派生 |
| `NetFlowTCPBegin()` | net_flow.go:15 | TCP 流开始派生 |
| `NetFlowTCPEnd()` | net_flow.go:82 | TCP 流结束派生 |
| `createPacketFromEvent()` | net_packet_helpers.go:148 | 从事件创建包 |
| `getProtoDNS()` | net_packet_helpers.go:523 | DNS 协议解析 |
| `DNSCache.Add()` | dnscache.go:48 | 添加 DNS 记录 |
| `DNSCache.Get()` | dnscache.go:84 | 查询 DNS 缓存 |

---

## 12. 常见问题与调试

### 12.1 网络事件未捕获

**症状**：启动 Tracee 但看不到网络事件

**排查步骤**：

```bash
# 1. 检查 cgroup v2 是否可用
mount | grep cgroup2

# 2. 检查 eBPF 程序是否加载
sudo bpftool prog list | grep cgroup_skb

# 3. 检查 cgroup 挂载
cat /proc/self/cgroup

# 4. 验证 perf buffer
sudo bpftool map list | grep net_cap
```

### 12.2 DNS 缓存未命中

**症状**：`net_flow_tcp_begin` 事件中域名字段为空

**原因**：DNS 响应在 TCP 连接之前未被捕获

**解决**：确保同时启用 DNS 事件

```bash
sudo ./dist/tracee -e net_packet_dns,net_flow_tcp_begin
```

### 12.3 性能优化建议

1. **使用事件过滤**：只捕获需要的事件
   ```bash
   sudo ./dist/tracee -e net_packet_dns --filter comm=curl
   ```

2. **限制捕获长度**：减少 pcap 数据量
   ```bash
   sudo ./dist/tracee --capture net --capture option:net-snaplen=96
   ```

3. **使用 ring buffer**（如果内核支持）：
   - 较新内核使用 BPF ring buffer 替代 perf buffer
   - 更低的 CPU 开销

---

## 13. 扩展阅读

### 13.1 相关内核文档

- [BPF_PROG_TYPE_CGROUP_SKB](https://docs.kernel.org/bpf/prog_cgroup_sysctl.html)
- [sk_buff 数据结构](https://elixir.bootlin.com/linux/latest/source/include/linux/skbuff.h)

### 13.2 协议规范

- [RFC 1035 - DNS](https://tools.ietf.org/html/rfc1035)
- [RFC 2616 - HTTP/1.1](https://tools.ietf.org/html/rfc2616)
- [RFC 793 - TCP](https://tools.ietf.org/html/rfc793)

### 13.3 相关项目

- [gopacket](https://github.com/google/gopacket) - Go 语言包解析库
- [cilium/ebpf](https://github.com/cilium/ebpf) - eBPF Go 库
- [libbpf](https://github.com/libbpf/libbpf) - eBPF C 库

---

## 总结

本章深入分析了 Tracee 的网络事件捕获机制：

1. **cgroup/skb 程序**：通过挂载到 cgroup v2 根目录，实现对所有容器和主机流量的监控
2. **两阶段处理**：kprobe 准备上下文，cgroup/skb 解析数据包
3. **协议分层解析**：按照 L3/L4/L7 层次递进解析
4. **网络流追踪**：通过 SYN+ACK 和 FIN/RST 标志追踪 TCP 连接生命周期
5. **DNS 缓存**：使用树状 LRU 缓存存储 DNS 解析结果
6. **事件派生**：内核提交基础事件，用户空间派生具体协议事件

理解这些机制后，你可以：
- 编写网络安全检测签名
- 扩展支持新的协议解析
- 优化网络事件处理性能
- 进行网络流量分析和取证

---

_最后更新：2025-01-22_
_维护者：Tracee 学习社区_
