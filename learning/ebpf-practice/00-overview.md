# Tracee eBPF 内核态代码学习指南

## 总览

本学习指南帮助你通过 Tracee 项目学习 eBPF 内核态编程。Tracee 是 Aqua Security 开源的运行时安全和取证工具，其 eBPF 实现涵盖了几乎所有主流的 eBPF 技术。

## 学习路线图

```
阶段 1: 基础入门
├── Demo 1: hello-exec (execve 追踪)
│   └── 学习: tracepoint, perf buffer, helper 函数
└── Demo 2: syscall-counter (系统调用计数)
    └── 学习: raw_tracepoint, Hash Map, 原子操作

阶段 2: 进程监控
└── Demo 3: process-tree (进程树构建)
    └── 学习: sched 类 tracepoint, CO-RE, task_struct

阶段 3: 文件系统
└── Demo 4: file-monitor (文件操作监控)
    └── 学习: kprobe/kretprobe, args_map 模式, 路径解析

阶段 4: 网络监控
└── Demo 5: connect-tracker (TCP 连接追踪)
    └── 学习: socket 结构, 字节序处理

阶段 5: 安全检测
├── Demo 6: capability-check (权限检测)
│   └── 学习: Linux Capabilities, LSM hooks
└── Demo 7: mprotect-alert (内存保护告警)
    └── 学习: W^X 检测, 内存保护
```

## 环境要求

### 硬件要求
- Linux 内核 >= 5.4 (推荐 5.15+)
- 至少 4GB RAM
- x86_64 或 ARM64 架构

### 软件安装

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install -y clang llvm libbpf-dev libelf-dev \
    linux-headers-$(uname -r) bpftool linux-tools-generic

# 验证 BTF 支持
ls /sys/kernel/btf/vmlinux

# 验证工具
clang --version
bpftool version
```

## 快速开始

```bash
# 进入 demos 目录
cd demos

# 检查依赖
make check-deps

# 编译所有 Demo
make all

# 运行第一个 Demo
sudo ./01-hello-exec/hello_exec
```

## Tracee 代码架构

### 核心文件

| 文件 | 行数 | 说明 |
|------|------|------|
| `pkg/ebpf/c/tracee.bpf.c` | 7566 | 主 eBPF 程序 |
| `pkg/ebpf/c/maps.h` | 746 | BPF Maps 定义 |
| `pkg/ebpf/c/types.h` | 651 | 数据类型定义 |
| `pkg/ebpf/c/common/*.h` | ~4500 | 22 个公共头文件 |

### 程序类型分布

| 类型 | 数量 | 用途 |
|------|------|------|
| raw_tracepoint | ~30 | 系统调用、进程事件 |
| kprobe | ~50 | VFS、LSM、内核函数 |
| kretprobe | ~15 | 函数返回值捕获 |
| cgroup_skb | 2 | 网络流量监控 |
| uprobe | ~8 | 用户空间追踪 |

## eBPF 核心概念

### 1. 程序类型 (SEC 宏)

```c
SEC("tracepoint/syscalls/sys_enter_execve")  // 系统调用 tracepoint
SEC("raw_tracepoint/sys_enter")              // 原始 tracepoint
SEC("kprobe/vfs_write")                      // 内核函数进入
SEC("kretprobe/vfs_write")                   // 内核函数返回
```

### 2. BPF Maps

```c
// Hash Map - 键值存储
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);
    __type(value, struct my_data);
} my_map SEC(".maps");

// Perf Event Array - 事件输出
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
} events SEC(".maps");
```

### 3. Helper 函数

| 函数 | 用途 |
|------|------|
| `bpf_get_current_pid_tgid()` | 获取 PID/TID |
| `bpf_get_current_comm()` | 获取进程名 |
| `bpf_get_current_task()` | 获取 task_struct |
| `bpf_probe_read_kernel()` | 读取内核内存 |
| `bpf_perf_event_output()` | 发送事件到用户态 |
| `bpf_map_lookup_elem()` | 查询 Map |
| `bpf_map_update_elem()` | 更新 Map |

### 4. CO-RE (Compile Once, Run Everywhere)

```c
// BPF_CORE_READ 安全读取内核结构
u32 pid = BPF_CORE_READ(task, tgid);

// 链式读取
u32 ppid = BPF_CORE_READ(task, real_parent, tgid);

// 等价于: task->real_parent->tgid
// 但处理了内核版本差异
```

## Demo 对应的 Tracee 代码

| Demo | Tracee 代码位置 | 行号 |
|------|-----------------|------|
| 1. hello-exec | syscall__execve | 364-482 |
| 2. syscall-counter | tracepoint__raw_syscalls__sys_enter | 45-60 |
| 3. process-tree | sched_process_fork | 602-757 |
| 4. file-monitor | trace_ret_vfs_write | 3325-3398 |
| 5. connect-tracker | security_socket_connect | 2696-2793 |
| 6. capability-check | cap_capable | 2530-2549 |
| 7. mprotect-alert | security_file_mprotect | 3680-3779 |

## 常见问题

### Q: 验证器报错 "invalid mem access"

A: 需要添加边界检查。使用 Tracee 的 `update_min` 宏模式。

### Q: 栈空间不足 (512 字节限制)

A: 使用 per-CPU array map 作为临时缓冲区。

### Q: 如何调试 eBPF 程序？

A:
```bash
# 使用 bpf_printk 调试
sudo cat /sys/kernel/debug/tracing/trace_pipe

# 查看加载的程序
sudo bpftool prog show

# 查看 Map 内容
sudo bpftool map dump name my_map
```

## 扩展学习

### Git Commit 案例

详见 [appendix-commits.md](./appendix-commits.md)

- `9f591d33`: 内联汇编约束 bug
- `5a727b30`: 线程栈识别算法改进
- `afb503db`: 位操作 bug 修复
- `3ac936c9`: Golang 堆检测精度修复
- `a675202e`: Clang 15 验证器兼容性

### 推荐资源

1. [libbpf-bootstrap](https://github.com/libbpf/libbpf-bootstrap) - eBPF 项目模板
2. [BPF CO-RE Reference Guide](https://nakryiko.com/posts/bpf-core-reference-guide/)
3. [Linux Kernel BPF Documentation](https://docs.kernel.org/bpf/)

## 目录结构

```
tracee_study/
├── demos/                      # 可编译运行的 Demo
│   ├── Makefile
│   ├── common/
│   │   ├── vmlinux.h
│   │   └── common.h
│   ├── 01-hello-exec/
│   ├── 02-syscall-counter/
│   ├── 03-process-tree/
│   ├── 04-file-monitor/
│   ├── 05-connect-tracker/
│   ├── 06-capability-check/
│   └── 07-mprotect-alert/
│
├── docs/ebpf-learning/         # 学习文档
│   ├── 00-overview.md          # 本文件
│   └── appendix-commits.md     # Git Commit 案例
│
└── pkg/ebpf/c/                 # Tracee 源码 (参考)
    ├── tracee.bpf.c
    ├── maps.h
    ├── types.h
    └── common/
```

## 下一步

1. 按顺序完成 7 个 Demo
2. 阅读对应的 Tracee 源码
3. 学习 Git Commit 案例
4. 尝试扩展练习
