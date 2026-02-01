# Demo 1: Hello Exec - execve 系统调用追踪

## 学习目标

通过这个 Demo，你将学习：

1. **eBPF 程序基本结构**
   - SEC() 宏定义程序类型
   - LICENSE 声明
   - BPF Maps 定义

2. **Tracepoint 的使用**
   - 如何找到 tracepoint
   - 如何获取 tracepoint 参数

3. **数据从内核传递到用户态**
   - Perf Event Array
   - bpf_perf_event_output()

4. **常用 Helper 函数**
   - bpf_get_current_pid_tgid()
   - bpf_get_current_comm()
   - bpf_probe_read_user_str()

## 文件说明

```
01-hello-exec/
├── hello_exec.bpf.c   # eBPF 内核态程序
├── hello_exec.c       # 用户态程序
└── README.md          # 本文件
```

## 编译和运行

```bash
# 进入 demos 目录
cd demos

# 编译
make demo1

# 运行 (需要 root 权限)
sudo ./01-hello-exec/hello_exec
```

## 预期输出

```
=============================================================
Demo 1: execve Tracing (Hello eBPF!)
=============================================================
Tracing execve system calls... Press Ctrl+C to exit.

TIME     | PID     | PPID    | UID   | COMM             | FILENAME
-------------------------------------------------------------
10:30:15 | 12345   | 12300   | 1000  | bash             | /usr/bin/ls
10:30:16 | 12346   | 12345   | 1000  | ls               | /usr/bin/cat
...
```

## 代码解析

### 1. Tracepoint 定义

```c
SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve_enter(struct execve_args *ctx)
```

- `tracepoint/syscalls/sys_enter_execve` 是 tracepoint 的路径
- 可以在 `/sys/kernel/debug/tracing/events/syscalls/` 查看所有 syscall tracepoints

### 2. 获取 Tracepoint 参数格式

```bash
# 查看 tracepoint 参数格式
cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_execve/format
```

输出示例：
```
name: sys_enter_execve
...
field:int __syscall_nr; offset:8; size:4; signed:1;
field:const char * filename; offset:16; size:8; signed:0;
field:const char *const * argv; offset:24; size:8; signed:0;
field:const char *const * envp; offset:32; size:8; signed:0;
```

### 3. Perf Buffer 工作流程

```
内核态 (BPF)                    用户态
    |                              |
    | bpf_perf_event_output()      |
    |----------------------------->|
    |                              | perf_buffer__poll()
    |                              | handle_event()
```

## 与 Tracee 代码对比

本 Demo 简化自 Tracee 的 execve 追踪实现：

| 特性 | Demo | Tracee |
|------|------|--------|
| 追踪点 | tracepoint | raw_tracepoint |
| 参数捕获 | filename 只 | filename + argv + envp |
| 事件结构 | 简单 | 完整 task_context |
| 过滤 | 无 | 多维度过滤 |

**Tracee 参考代码**: `pkg/ebpf/c/tracee.bpf.c:364-482`

## 练习题

1. **扩展练习**: 修改代码，同时捕获 `argv` 参数（提示：需要循环读取字符串数组）

2. **过滤练习**: 添加 UID 过滤，只追踪特定用户的 execve

3. **性能练习**: 使用 Ring Buffer 替代 Perf Buffer（需要内核 >= 5.8）

## 常见问题

### Q: 为什么需要 bpf_probe_read_user_str？

A: execve 的参数来自用户空间，直接解引用用户空间指针会导致内核崩溃。
   eBPF 验证器会阻止这种危险操作，必须使用安全的 helper 函数。

### Q: BPF_F_CURRENT_CPU 是什么意思？

A: 表示将事件写入当前 CPU 对应的 perf buffer。
   每个 CPU 有独立的 buffer，避免锁竞争，提高性能。

## 下一步

学习完本 Demo 后，继续 [Demo 2: syscall-counter](../02-syscall-counter/README.md)
学习如何使用 BPF Maps 统计系统调用。
