# Tracee 源代码学习指南 - 第三阶段：eBPF 内核侧实现

> **学习目标**：深入理解 eBPF 程序如何在内核中捕获事件并传递到用户空间
> **预计时间**：4-7 天
> **前置知识**：C 语言、Linux 内核基础、eBPF 基本概念、系统调用原理

---

## 📋 目录

1. [eBPF 程序架构](#1-ebpf-程序架构)
2. [系统调用拦截机制](#2-系统调用拦截机制)
3. [LSM Hook 安全事件](#3-lsm-hook-安全事件)
4. [Perf Buffer 数据传输](#4-perf-buffer-数据传输)
5. [BPF Maps 设计](#5-bpf-maps-设计)
6. [过滤机制](#6-过滤机制)
7. [实践练习](#7-实践练习)

---

## 1. eBPF 程序架构

### 1.1 文件结构

```
pkg/ebpf/c/
├── tracee.bpf.c              # 主 eBPF 程序 (7566 行)
├── tracee.h                  # 主头文件
├── maps.h                    # BPF Maps 定义
├── types.h                   # 数据类型定义
├── capture_filtering.h       # 捕获过滤逻辑
├── vmlinux.h                 # 内核类型定义 (BTF)
├── vmlinux_flavors.h         # 内核版本适配
├── vmlinux_missing.h         # 缺失的内核定义
│
└── common/                   # 通用辅助函数
    ├── arch.h               # 架构相关 (x86/ARM)
    ├── arguments.h          # 参数处理
    ├── buffer.h             # 缓冲区管理
    ├── context.h            # 上下文提取
    ├── filtering.h          # 过滤逻辑
    ├── filesystem.h         # 文件系统操作
    ├── network.h            # 网络协议处理
    ├── memory.h             # 内存操作
    └── ...
```

### 1.2 核心组件概览

```
┌─────────────────────────────────────────────────────────────────┐
│                  Tracee eBPF 程序架构                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  入口点 (Entry Points)                                           │
│  ┌────────────────────────────────────────────────────────────┐│
│  │ • sys_enter (系统调用入口)                                   ││
│  │ • sys_exit (系统调用出口)                                    ││
│  │ • LSM hooks (security_file_open, security_bprm_check...)    ││
│  │ • kprobes (vfs_write, tcp_connect...)                       ││
│  │ • tracepoints (sched_process_fork, sched_process_exec...)   ││
│  └────────────────────────────────────────────────────────────┘│
│                          │                                       │
│                          ▼                                       │
│  Tail Calls (分发到具体处理器)                                    │
│  ┌────────────────────────────────────────────────────────────┐│
│  │ sys_enter_init_tail[syscall_nr] ──▶ syscall_handler()      ││
│  │ • openat_handler                                            ││
│  │ • execve_handler                                            ││
│  │ • connect_handler                                           ││
│  │ • ...                                                       ││
│  └────────────────────────────────────────────────────────────┘│
│                          │                                       │
│                          ▼                                       │
│  核心处理逻辑                                                     │
│  ┌────────────────────────────────────────────────────────────┐│
│  │ 1. init_program_data() - 初始化程序数据                     ││
│  │ 2. evaluate_scope_filters() - 评估作用域过滤                ││
│  │ 3. save_to_submit_buf() - 保存事件数据到缓冲区              ││
│  │ 4. apply_data_filters() - 应用数据过滤                      ││
│  │ 5. events_perf_submit() - 提交事件到 Perf Buffer           ││
│  └────────────────────────────────────────────────────────────┘│
│                          │                                       │
│                          ▼                                       │
│  BPF Maps (状态存储)                                             │
│  ┌────────────────────────────────────────────────────────────┐│
│  │ • events (Perf Buffer) - 事件队列                           ││
│  │ • task_info_map - 任务信息缓存                               ││
│  │ • config_map - 配置参数                                      ││
│  │ • policies_map - 策略规则                                    ││
│  │ • filter_maps - 过滤表                                       ││
│  └────────────────────────────────────────────────────────────┘│
│                          │                                       │
│                          ▼                                       │
│                    Perf Buffer                                   │
│                    (传输到用户空间)                               │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## 2. 系统调用拦截机制

### 2.1 系统调用入口 - [pkg/ebpf/c/tracee.bpf.c:45](pkg/ebpf/c/tracee.bpf.c#L45)

```c
// trace/events/syscalls.h: TP_PROTO(struct pt_regs *regs, long id)
// 所有系统调用的初始入口点
SEC("raw_tracepoint/sys_enter")
int tracepoint__raw_syscalls__sys_enter(struct bpf_raw_tracepoint_args *ctx)
{
    // 获取当前任务结构
    struct task_struct *task = (struct task_struct *) bpf_get_current_task();

    // 提取系统调用号
    int id = ctx->args[1];

    // ========== 处理 32 位兼容模式 ==========
    if (is_compat(task)) {
        // 将 32 位系统调用号转换为 64 位
        u32 *id_64 = bpf_map_lookup_elem(&sys_32_to_64_map, &id);
        if (id_64 == 0)
            return 0;
        id = *id_64;
    }

    // ========== Tail Call 分发 ==========
    // 通过 tail call 跳转到对应的系统调用处理器
    // 这避免了单个 eBPF 程序的指令数限制
    bpf_tail_call(ctx, &sys_enter_init_tail, id);

    return 0;
}
```

**关键技术**：

1. **Raw Tracepoint**：
   - 比传统 kprobe 更稳定（内核 ABI）
   - 性能更好（无需符号解析）
   - 适用于所有系统调用

2. **Tail Call**：
   - 绕过 eBPF 单程序指令限制（1M 指令）
   - 跳转到专门的处理器，不返回
   - 类似函数调用但更高效

### 2.2 系统调用初始化 - [pkg/ebpf/c/tracee.bpf.c:67](pkg/ebpf/c/tracee.bpf.c#L67)

```c
// 系统调用的第一个 tail call 目标
// 职责：保存系统调用参数到 task_info_map
SEC("raw_tracepoint/sys_enter_init")
int sys_enter_init(struct bpf_raw_tracepoint_args *ctx)
{
    struct task_struct *task = (struct task_struct *) bpf_get_current_task();

    // ========== 获取或创建 task_info ==========
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tid = pid_tgid;  // 低 32 位是线程 ID

    task_info_t *task_info = bpf_map_lookup_elem(&task_info_map, &tid);
    if (unlikely(task_info == NULL)) {
        // 第一次见到这个线程，初始化
        task_info = init_task_info(tid, 0);
        if (unlikely(task_info == NULL))
            return 0;

        // 从 config_map 读取配置
        int zero = 0;
        config_entry_t *config = bpf_map_lookup_elem(&config_map, &zero);
        if (unlikely(config == NULL))
            return 0;

        // 初始化任务上下文（进程名、容器 ID 等）
        init_task_context(&task_info->context, task, config->options);
    }

    // ========== 提取系统调用参数 ==========
    syscall_data_t *sys = &(task_info->syscall_data);
    sys->id = ctx->args[1];  // 系统调用号

    struct pt_regs *regs = (struct pt_regs *) ctx->args[0];

    // 架构相关：从寄存器提取参数
    if (is_x86_compat(task)) {
        // 32 位 x86 使用不同的寄存器约定
#if defined(bpf_target_x86)
        sys->args.args[0] = BPF_CORE_READ(regs, bx);
        sys->args.args[1] = BPF_CORE_READ(regs, cx);
        sys->args.args[2] = BPF_CORE_READ(regs, dx);
        sys->args.args[3] = BPF_CORE_READ(regs, si);
        sys->args.args[4] = BPF_CORE_READ(regs, di);
        sys->args.args[5] = BPF_CORE_READ(regs, bp);
#endif
    } else {
        // 64 位或 ARM64
        sys->args.args[0] = PT_REGS_PARM1_CORE_SYSCALL(regs);
        sys->args.args[1] = PT_REGS_PARM2_CORE_SYSCALL(regs);
        sys->args.args[2] = PT_REGS_PARM3_CORE_SYSCALL(regs);
        sys->args.args[3] = PT_REGS_PARM4_CORE_SYSCALL(regs);
        sys->args.args[4] = PT_REGS_PARM5_CORE_SYSCALL(regs);
        sys->args.args[5] = PT_REGS_PARM6_CORE_SYSCALL(regs);
    }

    // ========== 继续 tail call 到通用提交函数 ==========
    bpf_tail_call(ctx, &sys_enter_submit_tail, TAIL_SYS_ENTER_SUBMIT);

    return 0;
}
```

**数据结构**：

```c
// 每个任务的信息缓存
typedef struct task_info {
    context_t context;         // 进程上下文（PID、容器 ID 等）
    syscall_data_t syscall_data;  // 当前系统调用数据
    u64 syscall_traced;        // 已跟踪的系统调用位图
    // ... 其他字段
} task_info_t;

// 系统调用数据
typedef struct syscall_data {
    int id;                    // 系统调用号
    args_t args;               // 6 个参数
    u64 ts;                    // 时间戳
} syscall_data_t;
```

### 2.3 系统调用处理示例：openat

让我们看一个完整的系统调用处理流程：

```c
// pkg/ebpf/c/tracee.bpf.c (具体行号根据版本不同)
SEC("kprobe/sys_openat")
int trace_openat(struct pt_regs *ctx)
{
    // ========== 1. 初始化程序数据 ==========
    program_data_t p = {};
    if (!init_program_data(&p, ctx, SYS_OPENAT))
        return 0;

    // ========== 2. 评估作用域过滤 ==========
    // 检查是否应该跟踪此进程/容器/UID
    if (!evaluate_scope_filters(&p))
        return 0;

    // ========== 3. 提取参数 ==========
    // openat(int dirfd, const char *pathname, int flags, mode_t mode)
    int dirfd = (int)PT_REGS_PARM1(ctx);
    void *pathname_ptr = (void *)PT_REGS_PARM2(ctx);
    int flags = (int)PT_REGS_PARM3(ctx);
    mode_t mode = (mode_t)PT_REGS_PARM4(ctx);

    // ========== 4. 保存参数到事件缓冲区 ==========
    save_to_submit_buf(&p.event->args_buf, (void *)&dirfd, sizeof(int), 0);
    save_str_to_buf(&p.event->args_buf, pathname_ptr, 1);
    save_to_submit_buf(&p.event->args_buf, (void *)&flags, sizeof(int), 2);
    save_to_submit_buf(&p.event->args_buf, (void *)&mode, sizeof(mode_t), 3);

    // ========== 5. 应用数据过滤 ==========
    // 例如：只监控特定路径
    if (!apply_data_filter(&p, pathname_ptr, FILTER_PATHNAME))
        return 0;

    // ========== 6. 提交事件到 Perf Buffer ==========
    events_perf_submit(&p, 0);

    return 0;
}
```

**核心函数详解**：

#### `init_program_data()`

```c
static __always_inline bool init_program_data(
    program_data_t *p,
    void *ctx,
    u32 event_id
) {
    // 获取当前 task_info
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tid = pid_tgid;

    task_info_t *task_info = bpf_map_lookup_elem(&task_info_map, &tid);
    if (!task_info)
        return false;

    // 初始化 program_data 结构
    p->event = get_buf(0);  // 从 per-CPU buffer 获取事件缓冲区
    if (!p->event)
        return false;

    p->task_info = task_info;
    p->ctx = ctx;

    // 填充事件基本信息
    p->event->event_id = event_id;
    p->event->ts = bpf_ktime_get_ns();
    p->event->pid = pid_tgid >> 32;
    p->event->tid = tid;

    // 复制任务上下文
    __builtin_memcpy(&p->event->context, &task_info->context, sizeof(context_t));

    return true;
}
```

#### `save_str_to_buf()` - 字符串参数保存

```c
static __always_inline int save_str_to_buf(
    args_buffer_t *buf,
    void *ptr,
    u8 index
) {
    // 从用户空间或内核空间读取字符串
    int size = bpf_probe_read_str(
        &buf->args[buf->offset],
        MAX_STRING_SIZE,
        ptr
    );

    if (size < 0)
        return -1;

    // 保存参数元数据
    buf->argnum++;
    save_u64_to_buf(buf, (u64)size, index | ARG_TYPE_STR);

    // 更新偏移量
    buf->offset += size;
    if (buf->offset > MAX_ARGS_BUF_SIZE - MAX_STRING_SIZE)
        buf->offset = MAX_ARGS_BUF_SIZE - MAX_STRING_SIZE;

    return size;
}
```

---

## 3. LSM Hook 安全事件

### 3.1 LSM 简介

LSM (Linux Security Modules) 提供了内核安全框架的 hook 点：

```
用户操作 → 系统调用 → VFS 层 → LSM Hook → 实际操作
                                  ↑
                                  └─ Tracee eBPF 程序可以在这里拦截
```

**优势**：
- 比系统调用更细粒度（一个系统调用可能触发多个 LSM hook）
- 提供安全上下文信息
- 更接近实际操作（已经过权限检查）

### 3.2 示例：security_file_open

```c
// pkg/ebpf/c/tracee.bpf.c
SEC("lsm/file_open")
int BPF_PROG(security_file_open, struct file *file)
{
    // ========== 1. 初始化 ==========
    program_data_t p = {};
    if (!init_program_data(&p, ctx, SECURITY_FILE_OPEN))
        return 0;

    // ========== 2. 评估过滤 ==========
    if (!evaluate_scope_filters(&p))
        return 0;

    // ========== 3. 提取文件信息 ==========
    struct path f_path = BPF_CORE_READ(file, f_path);
    struct dentry *dentry = BPF_CORE_READ(&f_path, dentry);
    struct inode *inode = BPF_CORE_READ(dentry, d_inode);

    // 获取文件路径
    void *path_buf = get_path_str(&f_path);

    // 获取文件标志
    unsigned int flags = BPF_CORE_READ(file, f_flags);

    // 获取 inode 信息
    unsigned long inode_nr = BPF_CORE_READ(inode, i_ino);
    dev_t dev = BPF_CORE_READ(inode, i_sb, s_dev);
    u64 ctime = BPF_CORE_READ(inode, i_ctime.tv_sec);

    // ========== 4. 保存参数 ==========
    save_str_to_buf(&p.event->args_buf, path_buf, 0);  // pathname
    save_to_submit_buf(&p.event->args_buf, &flags, sizeof(int), 1);  // flags
    save_to_submit_buf(&p.event->args_buf, &dev, sizeof(dev_t), 2);  // dev
    save_to_submit_buf(&p.event->args_buf, &inode_nr, sizeof(unsigned long), 3);  // inode
    save_to_submit_buf(&p.event->args_buf, &ctime, sizeof(u64), 4);  // ctime

    // ========== 5. 应用路径过滤 ==========
    if (!apply_pathname_filter(&p, path_buf))
        return 0;

    // ========== 6. 提交事件 ==========
    events_perf_submit(&p, 0);

    return 0;  // 返回 0 允许操作继续
}
```

### 3.3 常用 LSM Hooks

| Hook 名称 | 触发时机 | 用途 |
|-----------|---------|------|
| `security_bprm_check` | 执行新程序前 | 监控进程执行 |
| `security_file_open` | 打开文件时 | 监控文件访问 |
| `security_inode_unlink` | 删除文件时 | 监控文件删除 |
| `security_socket_create` | 创建 socket 时 | 监控网络活动 |
| `security_socket_connect` | 连接时 | 监控网络连接 |
| `security_socket_bind` | 绑定端口时 | 监控端口绑定 |
| `security_sb_mount` | 挂载文件系统时 | 监控挂载操作 |

---

## 4. Perf Buffer 数据传输

### 4.1 Perf Buffer 原理

```
┌───────────────────────────────────────────────────────────────┐
│                      Perf Buffer 架构                          │
├───────────────────────────────────────────────────────────────┤
│                                                                │
│  内核空间 (Per-CPU Buffers)                                    │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐        │
│  │  CPU 0       │  │  CPU 1       │  │  CPU N       │        │
│  │  Ring Buffer │  │  Ring Buffer │  │  Ring Buffer │        │
│  │  ┌────────┐  │  │  ┌────────┐  │  │  ┌────────┐  │        │
│  │  │ Event1 │  │  │  │ Event3 │  │  │  │ Event5 │  │        │
│  │  │ Event2 │  │  │  │ Event4 │  │  │  │ Event6 │  │        │
│  │  └────────┘  │  │  └────────┘  │  │  └────────┘  │        │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘        │
│         │                 │                 │                 │
│         └─────────────────┼─────────────────┘                 │
│                           │                                   │
├───────────────────────────┼───────────────────────────────────┤
│  用户空间                  │                                   │
│                           ▼                                   │
│                   ┌──────────────┐                            │
│                   │ Poll/Epoll   │                            │
│                   │ 事件通知      │                            │
│                   └──────┬───────┘                            │
│                          │                                    │
│                          ▼                                    │
│                   ┌──────────────┐                            │
│                   │ Read Events  │                            │
│                   │ (批量读取)    │                            │
│                   └──────────────┘                            │
│                                                                │
└───────────────────────────────────────────────────────────────┘
```

**特性**：
- **Per-CPU**：每个 CPU 独立缓冲区，无锁并发
- **环形缓冲**：覆盖最旧的事件（可配置）
- **批量读取**：减少上下文切换
- **异步通知**：epoll 机制

### 4.2 事件提交 - `events_perf_submit()`

```c
// pkg/ebpf/c/common/buffer.h
static __always_inline int events_perf_submit(
    program_data_t *p,
    u32 id
) {
    // 获取事件缓冲区
    event_data_t *event = p->event;
    if (!event)
        return -1;

    // 计算事件大小
    u32 size = sizeof(event_context_t) +
               sizeof(event_data_t) +
               event->args_buf.offset;

    // ========== 提交到 Perf Buffer ==========
    // bpf_perf_event_output() 是 eBPF 辅助函数
    // - ctx: 当前上下文
    // - events: Perf Buffer map
    // - BPF_F_CURRENT_CPU: 使用当前 CPU 的缓冲区
    // - event: 数据指针
    // - size: 数据大小
    int ret = bpf_perf_event_output(
        p->ctx,
        &events,
        BPF_F_CURRENT_CPU,
        event,
        size
    );

    // 更新统计
    if (ret == 0) {
        __sync_fetch_and_add(&p->task_info->context.event_count, 1);
    }

    return ret;
}
```

### 4.3 用户空间读取 - [pkg/ebpf/tracee.go](pkg/ebpf/tracee.go)

```go
// Go 侧创建和读取 Perf Buffer
func (t *Tracee) setupPerfBuffers() error {
    // ========== 创建事件 Perf Buffer ==========
    t.eventsPerfMap, err = t.bpfModule.InitPerfBuf(
        "events",                          // Map 名称
        t.eventsChannel,                   // 接收 channel
        t.lostEvChannel,                   // 丢失事件 channel
        t.config.PerfBufferSize,           // 缓冲区大小（页数）
    )

    // ========== 启动轮询 goroutine ==========
    go func() {
        for {
            // Poll 等待事件（阻塞调用）
            record, err := t.eventsPerfMap.Poll(300)  // 300ms 超时
            if err != nil {
                if errors.Is(err, io.EOF) {
                    return
                }
                logger.Errorw("Perf buffer poll error", "error", err)
                continue
            }

            // 读取事件数据
            eventBytes := record.RawSample
            if len(eventBytes) == 0 {
                continue
            }

            // ========== 发送到解码 channel ==========
            select {
            case t.eventsChannel <- eventBytes:
            default:
                // Channel 满，丢弃事件
                t.stats.EventsFiltered.Increment()
            }
        }
    }()

    return nil
}
```

---

## 5. BPF Maps 设计

### 5.1 Maps 类型和用途

```c
// pkg/ebpf/c/maps.h

// ========== 1. Perf Buffer (事件输出) ==========
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
    __uint(max_entries, 0);  // 0 表示自动设置为 CPU 数量
} events SEC(".maps");

// ========== 2. Hash Map (任务信息缓存) ==========
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(u32));      // Key: 线程 ID
    __uint(value_size, sizeof(task_info_t));  // Value: 任务信息
    __uint(max_entries, MAX_TASKS);     // 最大任务数
} task_info_map SEC(".maps");

// ========== 3. Array Map (配置) ==========
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(config_entry_t));
    __uint(max_entries, 1);  // 只有一个配置项
} config_map SEC(".maps");

// ========== 4. Hash Map (策略) ==========
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(u32));      // Key: 策略 ID
    __uint(value_size, sizeof(policy_t));
    __uint(max_entries, MAX_POLICIES);
} policies_map SEC(".maps");

// ========== 5. Prog Array (Tail Calls) ==========
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(key_size, sizeof(u32));      // Key: 系统调用号
    __uint(value_size, sizeof(u32));    // Value: 程序 FD
    __uint(max_entries, MAX_TAIL_CALL);
} sys_enter_init_tail SEC(".maps");

// ========== 6. LRU Hash (容器信息缓存) ==========
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(key_size, sizeof(u32));      // Key: Cgroup ID
    __uint(value_size, sizeof(container_info_t));
    __uint(max_entries, MAX_CONTAINERS);
} containers_map SEC(".maps");
```

### 5.2 Map 操作示例

```c
// 读取 Map
task_info_t *task_info = bpf_map_lookup_elem(&task_info_map, &tid);
if (!task_info) {
    // 处理未找到的情况
}

// 更新 Map
task_info_t new_task_info = {...};
bpf_map_update_elem(&task_info_map, &tid, &new_task_info, BPF_ANY);

// 删除 Map 条目
bpf_map_delete_elem(&task_info_map, &tid);

// 遍历 Map (仅用户空间支持，eBPF 不支持遍历)
// 在 Go 代码中:
// iter := t.bpfModule.GetMap("task_info_map").Iterator()
// for iter.Next(&key, &value) { ... }
```

---

## 6. 过滤机制

### 6.1 两级过滤架构

```
┌─────────────────────────────────────────────────────────┐
│                  Tracee 过滤架构                         │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  eBPF 内核侧 (早期过滤)                                   │
│  ┌────────────────────────────────────────────────────┐│
│  │                                                     ││
│  │  1. Scope Filter (作用域过滤)                       ││
│  │     • PID/TID                                       ││
│  │     • UID/GID                                       ││
│  │     • Container ID                                  ││
│  │     • Cgroup                                        ││
│  │     • Process Name                                  ││
│  │     ↓                                               ││
│  │  2. Event Filter (事件选择)                         ││
│  │     • 事件 ID 位图检查                               ││
│  │     • 策略规则匹配                                   ││
│  │     ↓                                               ││
│  │  3. Data Filter (数据过滤)                          ││
│  │     • 路径名过滤                                     ││
│  │     • 参数值过滤                                     ││
│  │     • 返回值过滤                                     ││
│  │                                                     ││
│  └────────────┬────────────────────────────────────────┘│
│               │                                          │
│               ▼ 通过的事件                                │
│         Perf Buffer                                      │
│               │                                          │
├───────────────┼──────────────────────────────────────────┤
│  用户空间 (后期过滤)                                      │
│               ▼                                          │
│  ┌────────────────────────────────────────────────────┐│
│  │                                                     ││
│  │  4. Policy Filter (策略过滤)                        ││
│  │     • 复杂条件判断                                   ││
│  │     • 多字段关联                                     ││
│  │     ↓                                               ││
│  │  5. Signature Filter (签名匹配)                     ││
│  │     • 行为模式检测                                   ││
│  │     • 威胁规则匹配                                   ││
│  │                                                     ││
│  └─────────────────────────────────────────────────────┘│
│                                                          │
└─────────────────────────────────────────────────────────┘
```

### 6.2 作用域过滤实现

```c
// pkg/ebpf/c/common/filtering.h
static __always_inline bool evaluate_scope_filters(program_data_t *p)
{
    task_info_t *task_info = p->task_info;
    context_t *context = &task_info->context;

    // 遍历所有策略
    for (int i = 0; i < MAX_POLICIES; i++) {
        policy_t *policy = bpf_map_lookup_elem(&policies_map, &i);
        if (!policy || !policy->enabled)
            continue;

        bool matched = true;

        // ========== 1. PID 过滤 ==========
        if (policy->pid_filter.enabled) {
            matched &= apply_equality_filter(
                &policy->pid_filter,
                p->event->pid
            );
        }

        // ========== 2. UID 过滤 ==========
        if (policy->uid_filter.enabled) {
            matched &= apply_equality_filter(
                &policy->uid_filter,
                context->uid
            );
        }

        // ========== 3. 容器过滤 ==========
        if (policy->container_filter.enabled) {
            // "new" 表示只监控新容器
            if (policy->container_filter.new_only) {
                matched &= (context->container_state == CONTAINER_CREATED);
            }

            // 容器 ID 列表匹配
            matched &= apply_container_filter(
                &policy->container_filter,
                context->container_id
            );
        }

        // ========== 4. 进程名过滤 ==========
        if (policy->comm_filter.enabled) {
            matched &= apply_string_filter(
                &policy->comm_filter,
                context->comm
            );
        }

        // 如果匹配任一策略，返回 true
        if (matched) {
            p->event->matched_policies |= (1ULL << i);
            return true;
        }
    }

    return false;
}
```

### 6.3 路径过滤示例

```c
// 路径名过滤器
static __always_inline bool apply_pathname_filter(
    program_data_t *p,
    const char *pathname
) {
    // 从 config 获取路径过滤规则
    config_entry_t *config = get_config(0);
    if (!config)
        return true;

    // 检查是否在黑名单中
    for (int i = 0; i < MAX_PATH_FILTERS; i++) {
        char *blacklist_path = config->pathname_filter.blacklist[i];
        if (blacklist_path[0] == '\0')
            break;

        // 前缀匹配
        if (has_prefix(pathname, blacklist_path))
            return false;  // 过滤掉
    }

    // 检查是否在白名单中（如果启用）
    if (config->pathname_filter.whitelist_enabled) {
        bool found = false;
        for (int i = 0; i < MAX_PATH_FILTERS; i++) {
            char *whitelist_path = config->pathname_filter.whitelist[i];
            if (whitelist_path[0] == '\0')
                break;

            if (has_prefix(pathname, whitelist_path)) {
                found = true;
                break;
            }
        }
        if (!found)
            return false;  // 不在白名单中，过滤掉
    }

    return true;  // 通过过滤
}
```

---

## 7. 实践练习

### 练习 1：编译和加载 eBPF 程序

```bash
# 1. 编译 eBPF 程序
cd /home/work/tracee
make bpf

# 2. 查看生成的 BPF 对象文件
ls -lh dist/tracee.bpf.core.o

# 3. 使用 bpftool 检查程序
bpftool prog list | grep tracee
bpftool map list | grep tracee

# 4. 查看 eBPF 程序的验证日志
sudo bpftool prog load dist/tracee.bpf.core.o /sys/fs/bpf/tracee --debug
```

### 练习 2：添加自定义日志

**目标**：在 eBPF 程序中添加日志输出

```c
// 在 pkg/ebpf/c/tracee.bpf.c 中添加
SEC("lsm/file_open")
int BPF_PROG(security_file_open, struct file *file)
{
    // 添加调试日志
    bpf_printk("file_open hook triggered, PID: %d\n", bpf_get_current_pid_tgid() >> 32);

    // ... 原有代码
}

// 重新编译并运行
make bpf
sudo ./dist/tracee -e security_file_open

// 在另一终端查看内核日志
sudo cat /sys/kernel/debug/tracing/trace_pipe | grep tracee
```

### 练习 3：分析 Perf Buffer 性能

**目标**：测量事件从内核到用户空间的延迟

```go
// 在 pkg/ebpf/events_pipeline.go 添加
func (t *Tracee) decodeEvents(...) {
    for rawEvent := range sourceChan {
        // 记录接收时间
        receiveTime := time.Now()

        // 解码事件
        ebpfEvent := t.eventsPool.Get().(*trace.Event)
        bufferdecoder.DecodeEvent(rawEvent, ebpfEvent, t.dataTypeDecoder)

        // 计算延迟
        kernelTime := time.Unix(0, int64(ebpfEvent.Timestamp))
        latency := receiveTime.Sub(kernelTime)

        logger.Debugw("Event latency",
            "event_id", ebpfEvent.EventID,
            "latency_us", latency.Microseconds(),
        )

        // ...
    }
}
```

### 练习 4：实现简单的 kprobe

**目标**：监控 `vfs_write` 函数调用

创建文件 `pkg/ebpf/c/custom_probe.c`：

```c
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

SEC("kprobe/vfs_write")
int trace_vfs_write(struct pt_regs *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    // 打印日志
    bpf_printk("vfs_write called by PID: %d\n", pid);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
```

编译和测试：

```bash
# 编译
clang -O2 -target bpf -c custom_probe.c -o custom_probe.o

# 加载
sudo bpftool prog load custom_probe.o /sys/fs/bpf/custom

# 附加到 kprobe
sudo bpftool prog attach pinned /sys/fs/bpf/custom kprobe vfs_write

# 查看日志
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

---

## 8. 总结与下一步

### 本阶段掌握的内容

- ✅ eBPF 程序结构和组织方式
- ✅ 系统调用拦截和 tail call 机制
- ✅ LSM hook 的使用
- ✅ Perf Buffer 数据传输原理
- ✅ BPF Maps 的设计和操作
- ✅ 多级过滤架构

### 关键文件清单

| 优先级 | 文件 | 核心内容 |
|--------|------|----------|
| 🔥🔥🔥 | `pkg/ebpf/c/tracee.bpf.c` | 主程序入口 |
| 🔥🔥🔥 | `pkg/ebpf/c/common/buffer.h` | 缓冲区管理 |
| 🔥🔥🔥 | `pkg/ebpf/c/common/filtering.h` | 过滤逻辑 |
| 🔥🔥 | `pkg/ebpf/c/maps.h` | BPF Maps 定义 |
| 🔥🔥 | `pkg/ebpf/c/common/context.h` | 上下文提取 |

### 下一步学习

继续第四阶段：**[Go 用户空间实现](04-userspace-implementation.md)**

重点内容：
- 事件解码器详细实现
- 进程树管理
- 容器信息获取
- DNS 缓存机制
- 策略管理器实现

---

**上一篇**：[第二阶段：事件处理流水线](02-event-pipeline.md) | **下一篇**：[第四阶段：用户空间实现](04-userspace-implementation.md)
