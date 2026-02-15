# Tracee eBPF 挂载点分类详解

本文档详细介绍 Tracee 使用的所有 eBPF 挂载点类型及其用途。

---

## 目录

- [1. 概述](#1-概述)
- [2. 挂载点类型分类](#2-挂载点类型分类)
- [3. Raw Tracepoint（原始追踪点）](#3-raw-tracepoint原始追踪点)
- [4. Kprobe/Kretprobe（内核探针）](#4-kprobekretprobe内核探针)
- [5. LSM Hook（Linux 安全模块钩子）](#5-lsm-hooklinux-安全模块钩子)
- [6. Uprobe（用户态探针）](#6-uprobe用户态探针)
- [7. CGroup SKB（CGroup Socket Buffer）](#7-cgroup-skbcgroup-socket-buffer)
- [8. 挂载点统计](#8-挂载点统计)
- [9. 挂载点选择策略](#9-挂载点选择策略)

---

## 1. 概述

### 1.1 什么是 eBPF 挂载点？

eBPF 挂载点（Probe/Hook Point）是 eBPF 程序附加到内核的特定位置。不同的挂载点类型决定了：
- **何时触发**：在什么事件或函数调用时执行
- **可访问的上下文**：可以获取哪些数据
- **性能开销**：对系统性能的影响程度
- **稳定性**：是否依赖内核内部实现细节

### 1.2 Tracee 挂载点类型

Tracee 使用以下 **7 种主要的 eBPF 挂载点类型**：

| 类型 | 数量 | 稳定性 | 性能 | 主要用途 |
|-----|------|--------|------|---------|
| **Raw Tracepoint** | ~30 | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | 系统调用、进程生命周期 |
| **Kprobe** | ~90 | ⭐⭐⭐ | ⭐⭐⭐ | 内核函数追踪 |
| **Kretprobe** | ~20 | ⭐⭐⭐ | ⭐⭐ | 内核函数返回值 |
| **LSM Hook** | ~1 | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | 安全策略执行点（需要 LSM BPF 支持）|
| **Uprobe** | ~10 | ⭐⭐⭐⭐ | ⭐⭐ | 用户态函数追踪 |
| **CGroup SKB** | 2 | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ | 网络数据包过滤 |
| **Tracepoint** | - | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | 内核追踪点（通过 Raw Tracepoint 使用）|

### 1.3 代码中的定义

在 [pkg/ebpf/probes/trace.go:18](../../../pkg/ebpf/probes/trace.go#L18) 中定义：

```go
type ProbeType uint8

const (
    KProbe        = iota // 内核函数探针
    KretProbe            // 内核函数返回探针
    Tracepoint           // 传统追踪点
    RawTracepoint        // 原始追踪点（性能更好）
    SyscallEnter         // 系统调用入口（特殊的 raw tracepoint）
    SyscallExit          // 系统调用出口（特殊的 raw tracepoint）
    Fentry               // 函数入口（内核 5.5+，暂未使用）
    LSM                  // Linux 安全模块钩子
    InvalidProbeType
)
```

---

## 2. 挂载点类型分类

### 2.1 按稳定性分类

#### 稳定的挂载点（推荐优先使用）

```
Raw Tracepoint  ← 内核 ABI 稳定，不依赖内核内部实现
LSM Hook        ← LSM 接口稳定
CGroup SKB      ← CGroup 接口稳定
Tracepoint      ← 内核追踪点稳定
```

**优点**：
- ✅ 跨内核版本兼容
- ✅ 不会因内核升级而失效
- ✅ 有稳定的参数接口

#### 不稳定的挂载点（需谨慎使用）

```
Kprobe          ← 依赖内核函数名称和签名
Kretprobe       ← 依赖内核函数实现
Uprobe          ← 依赖用户态二进制结构
```

**缺点**：
- ❌ 内核函数可能被重命名
- ❌ 函数参数可能改变
- ❌ 需要回退机制

### 2.2 按性能分类

#### 低开销

```
Raw Tracepoint  ← 直接访问内核数据结构，无额外封装
CGroup SKB      ← 网络栈高效过滤点
LSM Hook        ← 安全检查点，已存在的性能开销
```

#### 中等开销

```
Kprobe          ← 需要保存寄存器状态
Tracepoint      ← 传统追踪点有额外封装
```

#### 高开销

```
Kretprobe       ← 需要在函数入口和出口两次处理
Uprobe          ← 用户态和内核态切换开销
```

### 2.3 按功能分类

#### 系统调用追踪

```
raw_tracepoint/sys_enter           ← 所有系统调用入口
raw_tracepoint/sys_exit            ← 所有系统调用出口
raw_tracepoint/sys_enter_init      ← 系统调用初始化处理
raw_tracepoint/sys_exit_init       ← 系统调用退出处理
```

#### 进程生命周期

```
raw_tracepoint/sched_process_fork  ← 进程创建
raw_tracepoint/sched_process_exec  ← 进程执行
raw_tracepoint/sched_process_exit  ← 进程退出
raw_tracepoint/sched_process_free  ← 进程资源释放
kprobe/do_exit                     ← 进程退出内核函数
```

#### 文件操作

```
kprobe/vfs_write                   ← 文件写入
kretprobe/vfs_write                ← 文件写入返回
kprobe/vfs_read                    ← 文件读取
kretprobe/vfs_read                 ← 文件读取返回
kprobe/security_file_open          ← 文件打开安全检查
```

#### 网络操作

```
kprobe/security_socket_connect     ← Socket 连接
kprobe/security_socket_bind        ← Socket 绑定
kprobe/security_socket_accept      ← Socket 接受连接
kprobe/security_socket_sendmsg     ← 发送消息
kprobe/security_socket_recvmsg     ← 接收消息
cgroup_skb/ingress                 ← 入站网络数据包
cgroup_skb/egress                  ← 出站网络数据包
```

#### 安全操作

```
kprobe/security_bprm_check         ← 二进制执行检查
kprobe/commit_creds                ← 凭证提交（权限变更）
kprobe/cap_capable                 ← Capability 检查
kprobe/security_bpf                ← BPF 系统调用安全检查
kprobe/security_kernel_read_file   ← 内核读取文件
```

#### 容器相关

```
raw_tracepoint/cgroup_mkdir        ← CGroup 目录创建
raw_tracepoint/cgroup_rmdir        ← CGroup 目录删除
raw_tracepoint/cgroup_attach_task  ← 任务附加到 CGroup
```

#### 内核模块

```
raw_tracepoint/module_load         ← 模块加载
raw_tracepoint/module_free         ← 模块卸载
kprobe/do_init_module              ← 模块初始化
kretprobe/do_init_module           ← 模块初始化返回
```

---

## 3. Raw Tracepoint（原始追踪点）

### 3.1 概述

**Raw Tracepoint** 是最推荐的挂载点类型，提供：
- ✅ 最佳性能（直接访问内核数据结构）
- ✅ 最好的稳定性（内核 ABI 保证）
- ✅ 无需 BTF（Binary Type Format）支持

### 3.2 系统调用追踪

#### 核心入口/出口

```c
// 所有系统调用的统一入口
SEC("raw_tracepoint/sys_enter")
int tracepoint__raw_syscalls__sys_enter(struct bpf_raw_tracepoint_args *ctx)
{
    // 参数：ctx->args[1] = syscall_id
    // 功能：分发到具体的系统调用处理函数（通过 tail call）
}

// 所有系统调用的统一出口
SEC("raw_tracepoint/sys_exit")
int tracepoint__raw_syscalls__sys_exit(struct bpf_raw_tracepoint_args *ctx)
{
    // 参数：ctx->args[1] = return_value
    // 功能：获取系统调用返回值，提交事件
}
```

**处理流程**：
```
sys_enter
    ↓
sys_enter_init         ← 初始化上下文，保存参数
    ↓
具体系统调用处理      ← 通过 tail call 调用
    ↓
sys_enter_submit      ← 提交事件到 Perf Buffer
```

#### 特定系统调用

```c
// execve 系统调用（两个版本，用于不同的内核）
SEC("raw_tracepoint/sys_execve")
int syscall__execve(struct bpf_raw_tracepoint_args *ctx)

SEC("raw_tracepoint/sys_execveat")
int syscall__execveat(struct bpf_raw_tracepoint_args *ctx)

// init_module 系统调用
SEC("raw_tracepoint/sys_init_module")
int tracepoint__sys_init_module(struct bpf_raw_tracepoint_args *ctx)

// accept4 系统调用
SEC("raw_tracepoint/syscall__accept4")
int syscall__accept4(struct bpf_raw_tracepoint_args *ctx)
```

### 3.3 进程生命周期追踪

```c
// 进程创建（fork/clone/vfork）
SEC("raw_tracepoint/sched_process_fork")
int tracepoint__sched_process_fork(struct bpf_raw_tracepoint_args *ctx)
{
    // 参数：
    // ctx->args[0] = parent task_struct
    // ctx->args[1] = child task_struct
    // 用途：追踪进程树、容器检测
}

// 进程执行（execve）
SEC("raw_tracepoint/sched_process_exec")
int tracepoint__sched_process_exec(struct bpf_raw_tracepoint_args *ctx)
{
    // 参数：
    // ctx->args[0] = task_struct
    // ctx->args[1] = old_pid
    // ctx->args[2] = old_tid
    // 用途：进程启动检测、命令行参数捕获
}

// 进程退出
SEC("raw_tracepoint/sched_process_exit")
int tracepoint__sched_process_exit(struct bpf_raw_tracepoint_args *ctx)
{
    // 参数：ctx->args[0] = task_struct
    // 用途：进程退出事件、清理进程树
}

// 进程资源释放
SEC("raw_tracepoint/sched_process_free")
int tracepoint__sched_process_free(struct bpf_raw_tracepoint_args *ctx)
{
    // 参数：ctx->args[0] = task_struct
    // 用途：最终清理、LRU 缓存管理
}
```

### 3.4 调度器追踪

```c
// 进程切换
SEC("raw_tracepoint/sched_switch")
int tracepoint__sched_switch(struct bpf_raw_tracepoint_args *ctx)
{
    // 参数：
    // ctx->args[1] = prev task_struct
    // ctx->args[2] = next task_struct
    // 用途：追踪进程调度、CPU 使用情况
}
```

### 3.5 CGroup 追踪

```c
// CGroup 目录创建
SEC("raw_tracepoint/cgroup_mkdir")
int tracepoint__cgroup_mkdir(struct bpf_raw_tracepoint_args *ctx)
{
    // 参数：ctx->args[0] = cgroup kernfs_node
    // 用途：容器创建检测
}

// CGroup 目录删除
SEC("raw_tracepoint/cgroup_rmdir")
int tracepoint__cgroup_rmdir(struct bpf_raw_tracepoint_args *ctx)
{
    // 参数：ctx->args[0] = cgroup kernfs_node
    // 用途：容器删除检测
}

// 任务附加到 CGroup
SEC("raw_tracepoint/cgroup_attach_task")
int tracepoint__cgroup_attach_task(struct bpf_raw_tracepoint_args *ctx)
{
    // 参数：
    // ctx->args[0] = dst_cgrp
    // ctx->args[1] = leader task_struct
    // 用途：进程加入容器检测
}
```

### 3.6 模块追踪

```c
// 内核模块加载
SEC("raw_tracepoint/module_load")
int tracepoint__module_load(struct bpf_raw_tracepoint_args *ctx)
{
    // 参数：ctx->args[0] = module struct
    // 用途：Rootkit 检测、模块审计
}

// 内核模块卸载
SEC("raw_tracepoint/module_free")
int tracepoint__module_free(struct bpf_raw_tracepoint_args *ctx)
{
    // 参数：ctx->args[0] = module struct
    // 用途：模块卸载追踪
}
```

### 3.7 其他追踪点

```c
// 进程重命名
SEC("raw_tracepoint/task_rename")
int tracepoint__task_rename(struct bpf_raw_tracepoint_args *ctx)
{
    // 参数：
    // ctx->args[0] = task_struct
    // ctx->args[1] = old_comm
    // ctx->args[2] = new_comm
    // 用途：进程名变更检测（prctl PR_SET_NAME）
}
```

### 3.8 Raw Tracepoint 完整列表

| Raw Tracepoint | 用途 | 关键参数 |
|---------------|------|---------|
| `sys_enter` | 系统调用入口 | syscall_id |
| `sys_exit` | 系统调用出口 | return_value |
| `sys_enter_init` | 系统调用初始化 | - |
| `sys_exit_init` | 系统调用退出初始化 | - |
| `sys_enter_submit` | 提交系统调用事件 | - |
| `sys_exit_submit` | 提交系统调用退出事件 | - |
| `sys_execve` | execve 系统调用 | - |
| `sys_execveat` | execveat 系统调用 | - |
| `sys_init_module` | init_module 系统调用 | - |
| `syscall__accept4` | accept4 系统调用 | - |
| `sched_process_fork` | 进程创建 | parent, child |
| `sched_process_exec` | 进程执行 | task_struct |
| `sched_process_exit` | 进程退出 | task_struct |
| `sched_process_free` | 进程释放 | task_struct |
| `sched_switch` | 进程切换 | prev, next |
| `cgroup_mkdir` | CGroup 创建 | kernfs_node |
| `cgroup_rmdir` | CGroup 删除 | kernfs_node |
| `cgroup_attach_task` | 任务附加到 CGroup | cgroup, task |
| `module_load` | 模块加载 | module |
| `module_free` | 模块卸载 | module |
| `task_rename` | 进程重命名 | task, old_comm, new_comm |

---

## 4. Kprobe/Kretprobe（内核探针）

### 4.1 概述

**Kprobe** 可以附加到任意内核函数，但稳定性较差：
- ❌ 函数名可能在不同内核版本中改变
- ❌ 函数参数和返回值可能变化
- ✅ 灵活性高，可以追踪任何内核函数
- ✅ 适合追踪没有 tracepoint 的功能

**Kretprobe** 用于获取函数返回值：
- ❌ 性能开销更高（需要在入口和出口都处理）
- ✅ 可以关联函数的输入和输出

### 4.2 安全钩子（Security Hooks）

Tracee 大量使用 LSM (Linux Security Module) 框架的钩子函数：

#### 文件操作安全

```c
// 文件打开安全检查
SEC("kprobe/security_file_open")
int BPF_KPROBE(trace_security_file_open)
{
    // 参数：struct file *file
    // 用途：追踪文件访问、检测恶意文件打开
    // 优点：在实际打开前调用，可以阻止（如果使用 LSM BPF）
}

// 文件权限检查
SEC("kprobe/security_file_permission")
int BPF_KPROBE(trace_security_file_permission)
{
    // 参数：struct file *file, int mask
    // 用途：追踪文件访问权限检查
}

// 文件内存保护
SEC("kprobe/security_file_mprotect")
int BPF_KPROBE(trace_security_file_mprotect)
{
    // 参数：struct vm_area_struct *vma, unsigned long prot
    // 用途：检测可疑的内存保护修改（如 RWX 页面）
}

// 文件 ioctl 操作
SEC("kprobe/security_file_ioctl")
int BPF_KPROBE(trace_security_file_ioctl)
{
    // 用途：追踪设备控制操作
}
```

#### Socket 网络安全

```c
// Socket 创建
SEC("kprobe/security_socket_create")
int BPF_KPROBE(trace_security_socket_create)
{
    // 参数：int family, int type, int protocol
    // 用途：追踪 Socket 创建（TCP/UDP/ICMP）
}

// Socket 连接
SEC("kprobe/security_socket_connect")
int BPF_KPROBE(trace_security_socket_connect)
{
    // 参数：struct socket *sock, struct sockaddr *address
    // 用途：追踪网络连接（出站连接）
    // 应用：检测反向 Shell、C2 通信
}

// Socket 绑定
SEC("kprobe/security_socket_bind")
int BPF_KPROBE(trace_security_socket_bind)
{
    // 参数：struct socket *sock, struct sockaddr *address
    // 用途：追踪端口绑定（服务监听）
}

// Socket 监听
SEC("kprobe/security_socket_listen")
int BPF_KPROBE(trace_security_socket_listen)
{
    // 参数：struct socket *sock, int backlog
    // 用途：追踪服务开始监听
}

// Socket 接受连接
SEC("kprobe/security_socket_accept")
int BPF_KPROBE(trace_security_socket_accept)
{
    // 参数：struct socket *sock, struct socket *newsock
    // 用途：追踪入站连接接受
}

// Socket 发送消息
SEC("kprobe/security_socket_sendmsg")
int BPF_KPROBE(trace_security_socket_sendmsg)
{
    // 用途：追踪网络数据发送、DNS 查询检测
}

// Socket 接收消息
SEC("kprobe/security_socket_recvmsg")
int BPF_KPROBE(trace_security_socket_recvmsg)
{
    // 用途：追踪网络数据接收、DNS 响应检测
}

// Socket 选项设置
SEC("kprobe/security_socket_setsockopt")
int BPF_KPROBE(trace_security_socket_setsockopt)
{
    // 用途：追踪 Socket 选项修改
}
```

#### 进程和凭证安全

```c
// 二进制执行前检查
SEC("kprobe/security_bprm_check")
int BPF_KPROBE(trace_security_bprm_check)
{
    // 参数：struct linux_binprm *bprm
    // 用途：在 execve 执行前进行安全检查
    // 应用：检测可疑的可执行文件
}

// 凭证提交（权限变更）
SEC("kprobe/commit_creds")
int BPF_KPROBE(trace_commit_creds)
{
    // 参数：struct cred *new
    // 用途：追踪进程凭证变更（setuid/setgid/sudo）
    // 应用：权限提升检测
}

// Capability 检查
SEC("kprobe/cap_capable")
int BPF_KPROBE(trace_cap_capable)
{
    // 参数：struct cred *cred, int cap
    // 用途：追踪 Capability 使用（如 CAP_SYS_ADMIN）
    // 应用：特权操作审计
}

// 执行凭证准备
SEC("kprobe/security_bprm_creds_for_exec")
int BPF_KPROBE(trace_security_bprm_creds_for_exec)
{
    // 用途：追踪执行前的凭证设置
}
```

#### 文件系统安全

```c
// 文件系统挂载
SEC("kprobe/security_sb_mount")
int BPF_KPROBE(trace_security_sb_mount)
{
    // 参数：char *dev_name, char *type
    // 用途：追踪文件系统挂载
    // 应用：检测容器逃逸、挂载攻击
}

// 文件系统卸载
SEC("kprobe/security_sb_umount")
int BPF_KPROBE(trace_security_sb_umount)
{
    // 用途：追踪文件系统卸载
}

// Inode 删除
SEC("kprobe/security_inode_unlink")
int BPF_KPROBE(trace_security_inode_unlink)
{
    // 用途：追踪文件删除
}

// Inode 重命名
SEC("kprobe/security_inode_rename")
int BPF_KPROBE(trace_security_inode_rename)
{
    // 用途：追踪文件重命名
}

// Inode 创建设备节点
SEC("kprobe/security_inode_mknod")
int BPF_KPROBE(trace_security_inode_mknod)
{
    // 用途：追踪设备节点创建
}

// Inode 创建符号链接
SEC("kprobe/security_inode_symlink")
int BPF_KPROBE(trace_security_inode_symlink)
{
    // 用途：追踪符号链接创建
}
```

#### BPF 安全

```c
// BPF 系统调用
SEC("kprobe/security_bpf")
int BPF_KPROBE(trace_security_bpf)
{
    // 参数：int cmd, union bpf_attr *attr
    // 用途：追踪 BPF 程序加载、Map 操作
    // 应用：检测恶意 eBPF 程序
}

// BPF Map 操作
SEC("kprobe/security_bpf_map")
int BPF_KPROBE(trace_security_bpf_map)
{
    // 用途：追踪 BPF Map 创建和操作
}

// BPF 程序操作
SEC("kprobe/security_bpf_prog")
int BPF_KPROBE(trace_security_bpf_prog)
{
    // 用途：追踪 BPF 程序加载
}
```

#### 内核读取文件

```c
// 内核读取文件
SEC("kprobe/security_kernel_read_file")
int BPF_KPROBE(trace_security_kernel_read_file)
{
    // 参数：struct file *file, enum kernel_read_file_id id
    // 用途：追踪内核读取文件（模块加载、固件加载）
}

// 内核读取文件后处理
SEC("kprobe/security_kernel_post_read_file")
int BPF_KPROBE(trace_security_kernel_post_read_file)
{
    // 用途：追踪内核读取文件后的处理
}
```

#### 任务和时间安全

```c
// 任务资源限制
SEC("kprobe/security_task_setrlimit")
int BPF_KPROBE(trace_security_task_setrlimit)
{
    // 用途：追踪资源限制修改（ulimit）
}

// 任务 prctl
SEC("kprobe/security_task_prctl")
int BPF_KPROBE(trace_security_task_prctl)
{
    // 用途：追踪 prctl 系统调用
}

// 系统时间设置
SEC("kprobe/security_settime64")
int BPF_KPROBE(trace_security_settime64)
{
    // 用途：追踪系统时间修改
}

// 路径通知
SEC("kprobe/security_path_notify")
int BPF_KPROBE(trace_security_path_notify)
{
    // 用途：追踪 inotify/fanotify 监控设置
}
```

### 4.3 VFS（虚拟文件系统）操作

```c
// VFS 写入（kprobe + kretprobe 配合）
SEC("kprobe/vfs_write")
int BPF_KPROBE(trace_vfs_write_entry)
{
    // 入口：保存参数（文件、缓冲区、大小）
}

SEC("kretprobe/vfs_write")
int BPF_KPROBE(trace_vfs_write_return)
{
    // 返回：获取写入字节数
    // 用途：检测文件魔数修改、捕获写入内容
}

// VFS 写向量（writev）
SEC("kprobe/vfs_writev")
SEC("kretprobe/vfs_writev")

// 内核写入
SEC("kprobe/__kernel_write")
SEC("kretprobe/__kernel_write")

// VFS 读取
SEC("kprobe/vfs_read")
SEC("kretprobe/vfs_read")
{
    // 用途：捕获文件读取、检测敏感文件访问
}

// VFS 读向量（readv）
SEC("kprobe/vfs_readv")
SEC("kretprobe/vfs_readv")

// 文件时间更新
SEC("kprobe/vfs_utimes")
int BPF_KPROBE(trace_vfs_utimes)
{
    // 用途：追踪文件时间戳修改
}
```

### 4.4 内存操作

```c
// 内存映射地址
SEC("kprobe/security_mmap_addr")
int BPF_KPROBE(trace_security_mmap_addr)
{
    // 用途：追踪内存映射地址分配
}

// 内存映射文件
SEC("kprobe/security_mmap_file")
int BPF_KPROBE(trace_security_mmap_file)
{
    // 参数：struct file *file, unsigned long prot
    // 用途：追踪文件映射到内存
    // 应用：检测共享库注入
}

// do_mmap 函数
SEC("kprobe/do_mmap")
int BPF_KPROBE(trace_do_mmap_entry)

SEC("kretprobe/do_mmap")
int BPF_KPROBE(trace_do_mmap_return)
{
    // 用途：追踪内存映射操作
}
```

### 4.5 进程和命名空间

```c
// 进程退出
SEC("kprobe/do_exit")
int BPF_KPROBE(trace_do_exit)
{
    // 参数：long code (退出码)
    // 用途：追踪进程退出，清理资源
}

// 切换命名空间
SEC("kprobe/switch_task_namespaces")
int BPF_KPROBE(trace_switch_task_namespaces)
{
    // 用途：追踪命名空间切换
    // 应用：容器逃逸检测
}

// 用户模式助手
SEC("kprobe/call_usermodehelper")
int BPF_KPROBE(trace_call_usermodehelper)
{
    // 参数：char *path, char **argv
    // 用途：追踪内核调用用户态程序
    // 应用：检测可疑的内核到用户态执行
}

// 信号处理
SEC("kprobe/do_sigaction")
int BPF_KPROBE(trace_do_sigaction)
{
    // 用途：追踪信号处理器安装
}
```

### 4.6 内核模块和 eBPF

```c
// 模块初始化
SEC("kprobe/do_init_module")
int BPF_KPROBE(trace_do_init_module_entry)

SEC("kretprobe/do_init_module")
int BPF_KPROBE(trace_do_init_module_return)
{
    // 用途：追踪内核模块初始化
}

// Kprobe 注册
SEC("kprobe/register_kprobe")
int BPF_KPROBE(trace_register_kprobe_entry)

SEC("kretprobe/register_kprobe")
int BPF_KPROBE(trace_register_kprobe_return)
{
    // 用途：检测动态 kprobe 注册（可能的 rootkit）
}

// BPF 检查
SEC("kprobe/bpf_check")
int BPF_KPROBE(trace_bpf_check)
{
    // 用途：追踪 eBPF 程序验证
}

// BPF 辅助函数检查
SEC("kprobe/check_helper_call")
int BPF_KPROBE(trace_check_helper_call)
{
    // 用途：追踪 eBPF 程序使用的辅助函数
}

// BPF Map 函数兼容性检查
SEC("kprobe/check_map_func_compatibility")
int BPF_KPROBE(trace_check_map_func_compatibility)
{
    // 用途：追踪 eBPF Map 和函数兼容性检查
}
```

### 4.7 文件系统和设备

```c
// /proc 文件创建
SEC("kprobe/proc_create")
int BPF_KPROBE(trace_proc_create)
{
    // 用途：追踪 /proc 文件系统条目创建
    // 应用：检测 rootkit 隐藏
}

// debugfs 文件创建
SEC("kprobe/debugfs_create_file")
int BPF_KPROBE(trace_debugfs_create_file)

SEC("kprobe/debugfs_create_dir")
int BPF_KPROBE(trace_debugfs_create_dir)
{
    // 用途：追踪 debugfs 文件系统操作
}

// 设备添加
SEC("kprobe/device_add")
int BPF_KPROBE(trace_device_add)
{
    // 用途：追踪设备添加
}

// 字符设备注册
SEC("kprobe/__register_chrdev")
int BPF_KPROBE(trace_register_chrdev_entry)

SEC("kretprobe/__register_chrdev")
int BPF_KPROBE(trace_register_chrdev_return)
{
    // 用途：追踪字符设备注册
}
```

### 4.8 文件描述符操作

```c
// 文件描述符安装
SEC("kprobe/fd_install")
int BPF_KPROBE(trace_fd_install)
{
    // 用途：追踪文件描述符分配
}

// 文件关闭
SEC("kprobe/filp_close")
int BPF_KPROBE(trace_filp_close)
{
    // 用途：追踪文件关闭
}

// dup 系统调用
SEC("kprobe/sys_dup")
int BPF_KPROBE(trace_sys_dup)
{
    // 用途：追踪文件描述符复制
}
```

### 4.9 其他内核函数

```c
// splice 操作
SEC("kprobe/do_splice")
int BPF_KPROBE(trace_do_splice_entry)

SEC("kretprobe/do_splice")
int BPF_KPROBE(trace_do_splice_return)
{
    // 用途：检测 Dirty Pipe 漏洞利用
}

// ELF 头读取
SEC("kprobe/load_elf_phdrs")
int BPF_KPROBE(trace_load_elf_phdrs)
{
    // 用途：追踪 ELF 二进制加载
}

// 符号查找
SEC("kprobe/kallsyms_lookup_name")
int BPF_KPROBE(trace_kallsyms_lookup_name_entry)

SEC("kretprobe/kallsyms_lookup_name")
int BPF_KPROBE(trace_kallsyms_lookup_name_return)
{
    // 用途：检测内核符号地址查找（rootkit 常用）
}

// inotify 查找
SEC("kprobe/inotify_find_inode")
int BPF_KPROBE(trace_inotify_find_inode_entry)

SEC("kretprobe/inotify_find_inode")
int BPF_KPROBE(trace_inotify_find_inode_return)
{
    // 用途：追踪文件监控设置
}

// 文件修改时间
SEC("kprobe/file_update_time")
int BPF_KPROBE(trace_file_update_time_entry)

SEC("kretprobe/file_update_time")
int BPF_KPROBE(trace_file_update_time_return)

SEC("kprobe/file_modified")
int BPF_KPROBE(trace_file_modified_entry)

SEC("kretprobe/file_modified")
int BPF_KPROBE(trace_file_modified_return)
{
    // 用途：检测文件修改
}

// 文件截断
SEC("kprobe/do_truncate")
int BPF_KPROBE(trace_do_truncate)
{
    // 用途：追踪文件大小修改
}

// 权限修改
SEC("kprobe/chmod_common")
int BPF_KPROBE(trace_chmod_common)
{
    // 用途：追踪文件权限修改
}

// 工作目录修改
SEC("kprobe/set_fs_pwd")
int BPF_KPROBE(trace_set_fs_pwd)
{
    // 用途：追踪进程工作目录变更
}

// 目录遍历
SEC("kprobe/filldir64")
int BPF_KPROBE(trace_filldir64)
{
    // 用途：检测隐藏文件（rootkit）
}

// Tracepoint 探针注册
SEC("kprobe/tracepoint_probe_register_prio_may_exist")
int BPF_KPROBE(trace_tracepoint_probe_register)
{
    // 用途：检测动态 tracepoint 注册
}

// 执行二进制
SEC("kprobe/exec_binprm")
int BPF_KPROBE(trace_exec_binprm)
{
    // 用途：追踪二进制执行准备
}
```

### 4.10 网络相关（扩展）

```c
// Socket 分配文件
SEC("kprobe/sock_alloc_file")
int BPF_KPROBE(trace_sock_alloc_file_entry)

SEC("kretprobe/sock_alloc_file")
int BPF_KPROBE(trace_sock_alloc_file_return)
{
    // 用途：追踪 Socket 和文件描述符关联
}

// Socket 克隆
SEC("kprobe/security_sk_clone")
int BPF_KPROBE(trace_security_sk_clone)
{
    // 用途：追踪 Socket 克隆（accept）
}

// CGroup BPF 过滤器
SEC("kprobe/__cgroup_bpf_run_filter_skb")
int BPF_KPROBE(trace_cgroup_bpf_run_filter_skb)
{
    // 用途：追踪 CGroup eBPF 网络过滤器执行
}
```

---

## 5. LSM Hook（Linux 安全模块钩子）

### 5.1 概述

**LSM Hook** 是 Linux 内核提供的安全框架钩子点，特点：
- ✅ 稳定的 ABI（内核保证不变）
- ✅ 性能优异（内核本身的安全检查点）
- ✅ 可以在安全决策点拦截（LSM BPF 模式）
- ⚠️ 需要内核 5.7+ 和 CONFIG_BPF_LSM=y

### 5.2 LSM BPF 支持

Tracee 目前使用 **LSM BPF** 的一个钩子：

```c
// 文件打开 LSM 钩子
SEC("lsm/file_open")
int BPF_PROG(lsm_file_open, struct file *file, int ret)
{
    // 参数：
    // - file: 打开的文件结构
    // - ret: 前面 LSM 模块的返回值
    //
    // 用途：
    // - 在文件打开时进行安全检查
    // - 可以阻止文件打开（返回错误码）
    //
    // 优势：
    // - 比 kprobe/security_file_open 更稳定
    // - 可以强制执行安全策略（拒绝访问）
    //
    // 返回值：
    // - 0: 允许操作
    // - 负数: 拒绝操作（errno）
}
```

### 5.3 LSM vs Kprobe 对比

| 特性 | LSM Hook | Kprobe (security_*) |
|-----|----------|---------------------|
| **稳定性** | ⭐⭐⭐⭐⭐ 内核 ABI | ⭐⭐⭐ 依赖函数名 |
| **性能** | ⭐⭐⭐⭐⭐ 原生钩子 | ⭐⭐⭐⭐ 动态插桩 |
| **功能** | 可拦截操作 | 只能观察 |
| **要求** | 内核 5.7+ | 内核 3.10+ |
| **配置** | CONFIG_BPF_LSM | CONFIG_KPROBES |

### 5.4 为什么 Tracee 主要使用 Kprobe？

虽然 LSM BPF 更好，但 Tracee 主要使用 Kprobe 的原因：
1. **兼容性**：LSM BPF 需要较新内核（5.7+）
2. **历史原因**：Tracee 开发早于 LSM BPF 广泛支持
3. **功能需求**：当前只需观察，不需要强制拦截
4. **渐进迁移**：正在逐步迁移到 LSM BPF

**未来计划**：更多的 `security_*` kprobe 将迁移到 LSM Hook。

---

## 6. Uprobe（用户态探针）

### 6.1 概述

**Uprobe** 用于追踪用户态进程中的函数，特点：
- ✅ 可以追踪应用程序和共享库
- ✅ 不需要修改二进制文件
- ❌ 性能开销较高（用户态和内核态切换）
- ❌ 依赖二进制结构（地址、符号）

### 6.2 Tracee 中的 Uprobe

Tracee 的 Uprobe 主要用于 **内部机制**，而不是追踪用户程序：

#### 6.2.1 内核模块检测（LKM Seeker）

```c
// 主入口
SEC("uprobe/lkm_seeker")
int uprobe_lkm_seeker(struct pt_regs *ctx)
{
    // 用途：定期触发内核模块扫描
    // 触发方式：附加到 Tracee 自己的心跳函数
}

// 子扫描器（通过 tail call 分发）
SEC("uprobe/lkm_seeker_proc_tail")
int uprobe_lkm_seeker_proc_tail(struct pt_regs *ctx)
{
    // 扫描 /proc/modules
}

SEC("uprobe/lkm_seeker_kset_tail")
int uprobe_lkm_seeker_kset_tail(struct pt_regs *ctx)
{
    // 扫描内核 kset 链表
}

SEC("uprobe/lkm_seeker_mod_tree_tail")
int uprobe_lkm_seeker_mod_tree_tail(struct pt_regs *ctx)
{
    // 扫描内核 mod_tree
}

SEC("uprobe/lkm_seeker_new_mod_only_tail")
int uprobe_lkm_seeker_new_mod_only_tail(struct pt_regs *ctx)
{
    // 只扫描新加载的模块
}

SEC("uprobe/lkm_seeker_modtree_loop_tail")
int uprobe_lkm_seeker_modtree_loop_tail(struct pt_regs *ctx)
{
    // 模块树遍历循环
}

SEC("uprobe/lkm_seeker_submitter")
int uprobe_lkm_seeker_submitter(struct pt_regs *ctx)
{
    // 提交隐藏模块检测结果
}
```

**工作原理**：
1. Tracee 自己的用户态程序有一个心跳函数
2. eBPF uprobe 附加到这个心跳函数
3. 每次心跳触发时，eBPF 程序扫描内核模块
4. 对比多个数据源（/proc, kset, mod_tree）检测隐藏模块

#### 6.2.2 系统调用表检查

```c
SEC("uprobe/syscall_table_check")
int uprobe_syscall_table_check(struct pt_regs *ctx)
{
    // 用途：检查系统调用表是否被篡改
    // 方法：对比实际地址和预期地址
    // 应用：检测系统调用表 hook（rootkit 常用手法）
}
```

#### 6.2.3 序列操作检查

```c
SEC("uprobe/trigger_seq_ops_event")
int uprobe_trigger_seq_ops_event(struct pt_regs *ctx)
{
    // 用途：检测 seq_operations 结构被篡改
    // 应用：检测 /proc 文件系统隐藏（rootkit）
}
```

#### 6.2.4 内存转储

```c
SEC("uprobe/trigger_mem_dump_event")
int uprobe_trigger_mem_dump_event(struct pt_regs *ctx)
{
    // 用途：触发进程内存转储
    // 应用：取证分析、恶意软件分析
}
```

#### 6.2.5 心跳

```c
SEC("uprobe/capture_heartbeat")
int uprobe_capture_heartbeat(struct pt_regs *ctx)
{
    // 用途：Tracee 内部心跳机制
    // 功能：触发周期性任务
}
```

### 6.3 为什么使用 Uprobe？

**原因**：
1. **周期性任务**：内核没有提供定时器机制给 eBPF
2. **主动扫描**：需要主动扫描内核数据结构，而不是被动等待事件
3. **灵活控制**：可以从用户态控制扫描频率和策略

**替代方案**：
- 使用 `BPF_PROG_TYPE_TRACING` 的定时器（内核 5.15+）
- 但为了兼容性，仍使用 uprobe

---

## 7. CGroup SKB（CGroup Socket Buffer）

### 7.1 概述

**CGroup SKB** 程序在 cgroup 层级附加到网络栈，用于：
- ✅ 高效过滤容器网络流量
- ✅ 按容器级别的网络追踪
- ✅ 低开销（在网络栈早期处理）

### 7.2 入站和出站过滤器

```c
// 入站数据包过滤器
SEC("cgroup_skb/ingress")
int cgroup_skb_ingress(struct __sk_buff *skb)
{
    // 参数：
    // - skb: Socket buffer（网络数据包）
    //
    // 触发时机：
    // - 数据包进入 cgroup 网络命名空间时
    //
    // 用途：
    // - 追踪入站网络流量
    // - 过滤特定的网络协议
    // - 提取网络数据包元数据
    //
    // 可访问信息：
    // - 源/目标 IP 地址
    // - 源/目标端口
    // - 协议类型（TCP/UDP/ICMP）
    // - 数据包大小
    //
    // 返回值：
    // - 1: 允许数据包通过
    // - 0: 丢弃数据包
}

// 出站数据包过滤器
SEC("cgroup_skb/egress")
int cgroup_skb_egress(struct __sk_buff *skb)
{
    // 参数：同 ingress
    //
    // 触发时机：
    // - 数据包离开 cgroup 网络命名空间时
    //
    // 用途：
    // - 追踪出站网络流量
    // - 检测 C2 通信
    // - 监控容器网络活动
    //
    // 应用场景：
    // - 追踪容器到外部的连接
    // - 检测数据泄露
    // - 网络行为分析
}
```

### 7.3 工作流程

```
容器进程发送数据
    ↓
经过 cgroup_skb/egress
    ↓
进入网络栈
    ↓
到达目标
    ↓
接收方网络栈
    ↓
经过 cgroup_skb/ingress
    ↓
到达容器进程
```

### 7.4 与其他网络追踪的对比

| 方法 | 挂载点 | 性能 | 容器感知 | 数据完整性 |
|-----|-------|------|---------|-----------|
| **CGroup SKB** | CGroup 层 | ⭐⭐⭐⭐⭐ | ✅ 原生 | ⭐⭐⭐ 元数据 |
| **socket_connect** | LSM Hook | ⭐⭐⭐⭐ | ✅ 通过 cgroup | ⭐⭐⭐⭐ 连接信息 |
| **socket_sendmsg** | LSM Hook | ⭐⭐⭐ | ✅ 通过 cgroup | ⭐⭐⭐⭐⭐ 完整数据 |
| **XDP** | 网卡驱动 | ⭐⭐⭐⭐⭐ | ❌ 需要额外逻辑 | ⭐⭐⭐ 原始包 |
| **TC** | Traffic Control | ⭐⭐⭐⭐ | ❌ 需要额外逻辑 | ⭐⭐⭐⭐ 完整包 |

### 7.5 应用场景

```yaml
# 监控容器网络活动
scope:
  - container
events:
  - net_packet_ipv4  # 使用 cgroup_skb 捕获
  - net_packet_dns   # 使用 socket_sendmsg/recvmsg
```

**实现**：
- CGroup SKB 提供基础的数据包过滤
- 配合 socket kprobe 提供详细的网络信息
- 通过 cgroup ID 关联容器身份

---

## 8. 挂载点统计

### 8.1 按类型统计

根据 `tracee.bpf.c` 的统计：

```
Raw Tracepoint:     ~30 个
├─ sys_enter/exit:   8 个（系统调用）
├─ sched_*:          8 个（调度器）
├─ cgroup_*:         5 个（CGroup）
├─ module_*:         2 个（模块）
└─ 其他:             7 个

Kprobe:            ~90 个
├─ security_*:      ~30 个（安全钩子）
├─ vfs_*:           ~10 个（文件系统）
├─ socket/网络:     ~10 个
├─ BPF 相关:        ~5 个
├─ 模块相关:        ~5 个
└─ 其他:            ~30 个

Kretprobe:         ~20 个
├─ vfs_*:           ~6 个
├─ do_mmap:         1 个
├─ do_splice:       1 个
├─ kallsyms:        1 个
└─ 其他:            ~11 个

LSM Hook:          1 个
└─ file_open:       1 个

Uprobe:            ~10 个
└─ lkm_seeker 系列:  ~7 个
└─ 其他:            ~3 个

CGroup SKB:        2 个
├─ ingress:         1 个
└─ egress:          1 个
```

### 8.2 按功能统计

```
系统调用追踪:        ~15 个
进程生命周期:        ~10 个
文件系统操作:        ~20 个
网络操作:           ~15 个
安全和权限:         ~25 个
容器和 CGroup:      ~10 个
内核模块:           ~8 个
内存操作:           ~5 个
eBPF 和 BPF:        ~8 个
其他:               ~40 个
```

---

## 9. 挂载点选择策略

### 9.1 优先级推荐

Tracee 在选择挂载点时遵循以下优先级：

```
1. Raw Tracepoint  ← 最稳定、最快
   ↓
2. LSM Hook        ← 稳定、可拦截
   ↓
3. Kprobe          ← 灵活、但不稳定
   ↓
4. Kretprobe       ← 需要返回值时使用
   ↓
5. Uprobe          ← 特殊用途（心跳、扫描）
```

### 9.2 决策树

```
需要追踪的功能
    │
    ├─ 有 Tracepoint？
    │   ├─ 是 → 使用 Raw Tracepoint ✅
    │   └─ 否 ↓
    │
    ├─ 有 LSM Hook？
    │   ├─ 是 → 使用 LSM Hook ✅
    │   └─ 否 ↓
    │
    ├─ 需要返回值？
    │   ├─ 是 → Kprobe + Kretprobe
    │   └─ 否 → Kprobe
    │
    └─ 需要周期性执行？
        └─ 是 → Uprobe（心跳机制）
```

### 9.3 实例分析

#### 示例 1：追踪进程执行

```
选项 1: raw_tracepoint/sched_process_exec  ✅ 推荐
  优点：稳定、高性能、参数完整
  缺点：无

选项 2: kprobe/security_bprm_check
  优点：可以获取二进制路径
  缺点：不稳定、性能较差

选项 3: kprobe/exec_binprm
  优点：执行时机更早
  缺点：不稳定、参数可能变化
```

**Tracee 选择**：Raw Tracepoint（选项 1）

#### 示例 2：追踪文件打开

```
选项 1: lsm/file_open  ✅ 最佳（需要 5.7+）
  优点：最稳定、可拦截
  缺点：需要新内核

选项 2: kprobe/security_file_open  ✅ 当前使用
  优点：兼容性好
  缺点：稍不稳定

选项 3: 系统调用 open/openat
  优点：最稳定
  缺点：参数解析复杂、性能差
```

**Tracee 选择**：
- 主要：Kprobe（兼容性）
- 未来：LSM Hook（已实现，可切换）

#### 示例 3：追踪文件写入

```
选项 1: kprobe/vfs_write + kretprobe/vfs_write  ✅ 使用
  优点：捕获所有写入、可获取写入大小
  缺点：性能开销

选项 2: 系统调用 write/writev
  优点：用户态视角
  缺点：遗漏内核写入、性能差

选项 3: raw_tracepoint（不存在）
  不可行
```

**Tracee 选择**：Kprobe + Kretprobe（唯一选择）

### 9.4 兼容性处理

Tracee 使用 **回退机制** 处理内核差异：

```go
// 示例：文件打开追踪
func attachFileOpenProbe(module *bpf.Module) error {
    // 优先尝试 LSM Hook
    if supportLSM() && kernelVersion >= 5.7 {
        return attachLSMProbe(module, "file_open")
    }

    // 回退到 Kprobe
    return attachKProbe(module, "security_file_open")
}
```

在代码中的实现（[pkg/ebpf/probes/compatibility.go](../../../pkg/ebpf/probes/compatibility.go)）：

```go
type ProbeCompatibility struct {
    requirements []CompatibilityRequirement
}

// 检查探针是否兼容当前环境
func (p *ProbeCompatibility) isCompatible(env EnvironmentProvider) (bool, error) {
    for _, req := range p.requirements {
        compatible, err := req.Check(env)
        if err != nil || !compatible {
            return false, err
        }
    }
    return true, nil
}
```

---

## 10. 总结

### 10.1 关键要点

1. **Raw Tracepoint 是首选**
   - 最稳定、最快、最兼容
   - 用于系统调用、进程生命周期、CGroup

2. **LSM Hook 是未来**
   - 正在逐步迁移
   - 更稳定、可拦截操作

3. **Kprobe 作为补充**
   - 用于没有 tracepoint 的功能
   - 需要考虑兼容性

4. **CGroup SKB 用于网络**
   - 容器级别的网络追踪
   - 高性能、低开销

5. **Uprobe 用于内部机制**
   - 心跳、周期性任务
   - 不用于追踪用户程序

### 10.2 最佳实践

1. **新功能开发**：
   - 优先查找 Raw Tracepoint
   - 考虑使用 LSM Hook
   - 最后才使用 Kprobe

2. **兼容性设计**：
   - 实现多个版本（LSM + Kprobe）
   - 运行时检测并选择
   - 提供降级路径

3. **性能优化**：
   - 使用 Raw Tracepoint 替代 Kprobe
   - 减少 Kretprobe 使用
   - 在 eBPF 中进行早期过滤

4. **稳定性保证**：
   - 避免依赖内核内部函数
   - 使用稳定的 ABI
   - 测试多个内核版本

### 10.3 扩展阅读

- [eBPF 官方文档](https://ebpf.io/)
- [BCC 参考指南](https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md)
- [内核文档：LSM BPF](https://www.kernel.org/doc/html/latest/bpf/prog_lsm.html)
- [内核文档：Tracepoint](https://www.kernel.org/doc/html/latest/trace/tracepoints.html)

---

**相关文档：**
- [Tracee 架构概览](./01-architecture-overview.md)
- [eBPF 实现详解](./03-ebpf-implementation.md)
- [事件追踪](./02-event-pipeline.md)
