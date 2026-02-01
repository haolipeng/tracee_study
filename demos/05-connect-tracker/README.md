# Demo 5: Connect Tracker - 网络连接追踪

## 学习目标

1. **Socket 操作追踪**
   - security_socket_connect
   - security_socket_accept

2. **网络数据结构**
   - struct socket / struct sock
   - struct sockaddr_in / sockaddr_in6

3. **字节序处理**
   - bpf_ntohs / bpf_ntohl
   - 网络字节序 vs 主机字节序

## 编译和运行

```bash
cd demos
make demo5
sudo ./05-connect-tracker/connect_tracker
```

## 预期输出

```
=============================================================
Demo 5: TCP/UDP Connection Tracker
=============================================================
TIME     PRO PID     COMM             CONNECTION
-------------------------------------------------------------
10:30:15 TCP 1234    curl             *:0     -> 142.250.185.78:443
10:30:16 TCP 5678    ssh              *:0     -> 192.168.1.100:22
```

## 核心代码解析

### 1. 获取连接地址

```c
SEC("kprobe/security_socket_connect")
int BPF_KPROBE(trace_connect, struct socket *sock, struct sockaddr *address, int addrlen)
{
    u16 family = get_sockaddr_family(address);

    if (family == AF_INET) {
        struct sockaddr_in *addr = (struct sockaddr_in *)address;
        bpf_probe_read_kernel(&event->daddr_v4, ..., &addr->sin_addr);
        bpf_probe_read_kernel(&event->dport, ..., &addr->sin_port);
        event->dport = bpf_ntohs(event->dport);  // 网络字节序转换
    }
}
```

### 2. 从 sock 结构获取地址

```c
struct sock *sk = BPF_CORE_READ(sock, sk);

// IPv4 地址在 __sk_common 中
event->saddr_v4 = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
event->daddr_v4 = BPF_CORE_READ(sk, __sk_common.skc_daddr);
event->sport = BPF_CORE_READ(sk, __sk_common.skc_num);
event->dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
```

## 与 Tracee 对比

| 特性 | Demo | Tracee |
|------|------|--------|
| 连接追踪 | connect/accept | + bind/listen |
| 协议支持 | TCP/UDP | + Unix socket |
| 流量分析 | 无 | DNS/HTTP 解析 |

**Tracee 参考**: `pkg/ebpf/c/tracee.bpf.c:2696-2793`

## 练习题

1. **DNS 追踪**：追踪 UDP 53 端口流量

2. **连接计数**：统计每个进程的连接数

3. **黑名单**：阻止连接到特定 IP
