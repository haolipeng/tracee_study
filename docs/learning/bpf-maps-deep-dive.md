# BPF Maps 深度解析

> 预估学习时长：2-3天 | 难度：高级 (4/5)

## 概述

BPF Maps 是 eBPF 程序与用户空间通信的核心数据结构，也是在 eBPF 程序之间共享状态的关键机制。在 Tracee 项目中，Maps 被广泛用于：

- **事件过滤**：根据 PID、UID、容器等条件过滤事件
- **状态存储**：保存进程信息、任务上下文等运行时状态
- **配置传递**：将用户空间配置传递给内核态程序
- **事件输出**：通过 Perf Event Array 将事件发送到用户空间
- **尾调用路由**：使用 Program Array 实现程序间跳转

## 学习目标

完成本章学习后，你将能够：

1. 理解 BPF Maps 的基本概念和各种类型
2. 掌握 Tracee 中使用的 40+ 种 Maps 的用途
3. 理解内核态 Maps 操作（lookup、update、delete）
4. 掌握用户空间 Maps 访问方法
5. 理解 Map of Maps 的高级用法
6. 分析 Maps 的性能特性和内存管理
7. 独立调试 Maps 相关问题

---

## 1. BPF Maps 基础知识

### 1.1 什么是 BPF Maps？

BPF Maps 是驻留在内核中的键值存储结构，具有以下特点：

```
+------------------+     +------------------+
|   User Space     |     |   Kernel Space   |
|                  |     |                  |
|  libbpf/Go app   |<--->|   BPF Program    |
|                  |     |                  |
+--------+---------+     +--------+---------+
         |                        |
         v                        v
    +----+------------------------+----+
    |           BPF Maps               |
    |  (Kernel Memory, Shared State)   |
    +----------------------------------+
```

**关键特性：**
- 在内核内存中分配
- 可被多个 eBPF 程序共享
- 用户空间可通过文件描述符访问
- 支持多种数据结构类型
- 具有原子操作保证

### 1.2 Maps 定义语法（BTF 格式）

Tracee 使用现代 BTF（BPF Type Format）语法定义 Maps：

```c
// 基本 Hash Map 定义
struct containers_map {
    __uint(type, BPF_MAP_TYPE_HASH);    // Map 类型
    __uint(max_entries, 10240);          // 最大条目数
    __type(key, u32);                    // 键类型
    __type(value, u8);                   // 值类型
} containers_map SEC(".maps");

typedef struct containers_map containers_map_t;
```

**语法说明：**
- `__uint(type, ...)`: 指定 Map 类型
- `__uint(max_entries, ...)`: 最大容量
- `__type(key, ...)`: 键的数据类型
- `__type(value, ...)`: 值的数据类型
- `SEC(".maps")`: 将 Map 放入特殊 ELF section

### 1.3 常用 Map 类型对比

| Map 类型 | 查找复杂度 | 用途 | 内存模型 |
|---------|-----------|------|---------|
| `BPF_MAP_TYPE_HASH` | O(1) | 键值查找 | 动态分配 |
| `BPF_MAP_TYPE_ARRAY` | O(1) | 索引访问 | 预分配 |
| `BPF_MAP_TYPE_LRU_HASH` | O(1) | 自动淘汰 | 动态+LRU |
| `BPF_MAP_TYPE_PERCPU_ARRAY` | O(1) | 无锁并发 | Per-CPU |
| `BPF_MAP_TYPE_PERF_EVENT_ARRAY` | - | 事件流 | Ring Buffer |
| `BPF_MAP_TYPE_PROG_ARRAY` | O(1) | 尾调用 | 程序引用 |
| `BPF_MAP_TYPE_HASH_OF_MAPS` | O(1) | 嵌套Maps | 动态 |
| `BPF_MAP_TYPE_LPM_TRIE` | O(k) | 前缀匹配 | Trie结构 |
| `BPF_MAP_TYPE_STACK_TRACE` | O(1) | 栈追踪 | 特殊 |

---

## 2. Tracee Maps 完整清单

Tracee 定义了超过 40 个 BPF Maps，按功能分类如下：

### 2.1 配置与状态 Maps

| Map 名称 | 类型 | 用途 |
|---------|------|------|
| `config_map` | ARRAY | 全局配置（tracee_pid, options等） |
| `kconfig_map` | HASH | 内核配置变量 |
| `netconfig_map` | ARRAY | 网络捕获配置 |
| `ksymbols_map` | HASH | 内核符号地址表 |

### 2.2 进程与任务 Maps

| Map 名称 | 类型 | 用途 |
|---------|------|------|
| `proc_info_map` | LRU_HASH | 进程信息缓存 |
| `task_info_map` | LRU_HASH | 任务（线程）信息 |
| `containers_map` | HASH | 容器 cgroup 状态 |
| `args_map` | HASH | 系统调用参数暂存 |

### 2.3 过滤器 Maps（支持版本化）

| Map 名称 | 类型 | 用途 |
|---------|------|------|
| `uid_filter` / `uid_filter_version` | HASH / HASH_OF_MAPS | UID 过滤 |
| `pid_filter` / `pid_filter_version` | HASH / HASH_OF_MAPS | PID 过滤 |
| `comm_filter` / `comm_filter_version` | HASH / HASH_OF_MAPS | 命令名过滤 |
| `binary_filter` / `binary_filter_version` | HASH / HASH_OF_MAPS | 二进制路径过滤 |
| `mnt_ns_filter` / `mnt_ns_filter_version` | HASH / HASH_OF_MAPS | Mount NS 过滤 |
| `pid_ns_filter` / `pid_ns_filter_version` | HASH / HASH_OF_MAPS | PID NS 过滤 |
| `uts_ns_filter` / `uts_ns_filter_version` | HASH / HASH_OF_MAPS | UTS NS 过滤 |
| `cgroup_id_filter` / `cgroup_id_filter_version` | HASH / HASH_OF_MAPS | Cgroup 过滤 |
| `process_tree_map` / `process_tree_map_version` | HASH / HASH_OF_MAPS | 进程树过滤 |

### 2.4 数据过滤器 Maps

| Map 名称 | 类型 | 用途 |
|---------|------|------|
| `data_filter_exact` | HASH | 精确字符串匹配 |
| `data_filter_prefix` | LPM_TRIE | 前缀匹配 |
| `data_filter_suffix` | LPM_TRIE | 后缀匹配 |
| `events_map` / `events_map_version` | HASH / HASH_OF_MAPS | 事件配置 |

### 2.5 尾调用 Program Arrays

| Map 名称 | 类型 | 用途 |
|---------|------|------|
| `prog_array` | PROG_ARRAY | 通用尾调用 |
| `prog_array_tp` | PROG_ARRAY | Tracepoint 尾调用 |
| `sys_enter_tails` | PROG_ARRAY | 系统调用入口处理 |
| `sys_exit_tails` | PROG_ARRAY | 系统调用出口处理 |
| `sys_enter_init_tail` | PROG_ARRAY | 系统调用初始化 |
| `sys_exit_init_tail` | PROG_ARRAY | 系统调用清理 |
| `sys_enter_submit_tail` | PROG_ARRAY | 入口事件提交 |
| `sys_exit_submit_tail` | PROG_ARRAY | 出口事件提交 |
| `generic_sys_enter_tails` | PROG_ARRAY | 通用入口处理 |
| `generic_sys_exit_tails` | PROG_ARRAY | 通用出口处理 |

### 2.6 缓冲区 Maps

| Map 名称 | 类型 | 用途 |
|---------|------|------|
| `bufs` | PERCPU_ARRAY | 通用数据缓冲区 |
| `event_data_map` | PERCPU_ARRAY | 事件数据暂存 |
| `signal_data_map` | PERCPU_ARRAY | 信号数据暂存 |
| `scratch_map` | PERCPU_ARRAY | 临时工作区 |
| `data_filter_bufs` | PERCPU_ARRAY | 数据过滤缓冲 |
| `data_filter_lpm_bufs` | PERCPU_ARRAY | LPM 过滤缓冲 |

### 2.7 Perf Event Arrays（事件输出）

| Map 名称 | 类型 | 用途 |
|---------|------|------|
| `events` | PERF_EVENT_ARRAY | 主事件流 |
| `file_writes` | PERF_EVENT_ARRAY | 文件写入事件 |
| `signals` | PERF_EVENT_ARRAY | 控制平面信号 |
| `logs` | PERF_EVENT_ARRAY | BPF 日志输出 |

### 2.8 特殊用途 Maps

| Map 名称 | 类型 | 用途 |
|---------|------|------|
| `stack_addresses` | STACK_TRACE | 栈地址存储 |
| `fd_arg_path_map` | LRU_HASH | FD 路径缓存 |
| `file_modification_map` | LRU_HASH | 文件修改追踪 |
| `io_file_path_cache_map` | LRU_HASH | IO 路径缓存 |
| `elf_files_map` | LRU_HASH | ELF 文件缓存 |
| `bpf_attach_map` | LRU_HASH | BPF 程序附加信息 |
| `syscall_source_map` | LRU_HASH | 异常系统调用来源 |
| `expected_sys_call_table` | ARRAY | 预期系统调用表 |
| `sys_32_to_64_map` | HASH | 32位转64位系统调用 |
| `logs_count` | HASH | 日志计数 |

---

## 3. Maps 类型详解

### 3.1 Hash Maps

Hash Map 是最常用的 Map 类型，提供 O(1) 的键值查找。

**定义示例（`pkg/ebpf/c/maps.h`）：**

```c
// 内核符号地址映射
struct ksymbols_map {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, ksym_name_t);      // 符号名字符串
    __type(value, u64);             // 内核地址
} ksymbols_map SEC(".maps");
```

**内核态操作：**

```c
// 查找符号地址
statfunc void *get_symbol_address(const char *name)
{
    ksym_name_t new_ksym_name = {};
    bpf_probe_read_kernel_str(&new_ksym_name.str, MAX_KSYM_NAME_SIZE, name);

    void **sym = bpf_map_lookup_elem(&ksymbols_map, (void *)&new_ksym_name);
    if (sym == NULL)
        return NULL;
    return *sym;
}
```

**用户态操作（Go）：**

```go
// pkg/ebpf/ksymbols.go
func (t *Tracee) UpdateKallsyms() error {
    bpfKsymsMap, err := t.bpfModule.GetMap("ksymbols_map")
    if err != nil {
        return err
    }

    for _, sym := range symbol {
        key := make([]byte, maxKsymNameLen)
        copy(key, sym.Name)
        addr := sym.Address

        err := bpfKsymsMap.Update(
            unsafe.Pointer(&key[0]),
            unsafe.Pointer(&addr),
        )
        if err != nil {
            return err
        }
    }
    return nil
}
```

### 3.2 LRU Hash Maps

LRU Hash 在容量满时自动淘汰最少使用的条目，适合缓存场景。

**定义示例：**

```c
// 进程信息缓存，最多30720条目
struct proc_info_map {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 30720);
    __type(key, u32);              // host_pid
    __type(value, proc_info_t);    // 进程详细信息
} proc_info_map SEC(".maps");

// 任务信息缓存
struct task_info_map {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);              // host_tid
    __type(value, task_info_t);    // 任务详细信息
} task_info_map SEC(".maps");
```

**LRU 特性利用：**

```c
// 获取或初始化任务信息
statfunc task_info_t *get_or_init_task_info(u32 tid)
{
    task_info_t *task_info = bpf_map_lookup_elem(&task_info_map, &tid);
    if (task_info != NULL)
        return task_info;

    // 不存在则初始化
    task_info = init_task_info(tid, 0);
    return task_info;  // LRU 会自动淘汰旧条目
}
```

### 3.3 Array Maps

Array Map 使用整数索引，所有条目预分配，适合固定大小配置。

**定义示例：**

```c
// 全局配置（只有1个条目）
struct config_map {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, config_entry_t);
} config_map SEC(".maps");

// 预期系统调用表
struct expected_sys_call_table {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_SYS_CALL_TABLE_SIZE);
    __type(key, u32);
    __type(value, syscall_table_entry_t);
} expected_sys_call_table SEC(".maps");
```

**用户态更新配置（Go）：**

```go
// pkg/ebpf/config.go
type Config struct {
    TraceePid       uint32
    Options         uint32
    CgroupV1Hid     uint32
    _               uint16  // padding
    PoliciesVersion uint16
    PoliciesConfig  policy.PoliciesConfig
}

func (c *Config) UpdateBPF(bpfModule *bpf.Module) error {
    bpfConfigMap, err := bpfModule.GetMap("config_map")
    if err != nil {
        return err
    }

    cZero := uint32(0)
    return bpfConfigMap.Update(
        unsafe.Pointer(&cZero),
        unsafe.Pointer(c),
    )
}
```

### 3.4 Per-CPU Maps

Per-CPU Map 为每个 CPU 核心维护独立副本，避免锁竞争。

**定义示例：**

```c
// Per-CPU 缓冲区
struct bufs {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, MAX_BUFFERS);
    __type(key, u32);
    __type(value, buf_t);  // 大型缓冲区结构
} bufs SEC(".maps");

// Per-CPU 事件数据
struct event_data_map {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, event_data_t);
} event_data_map SEC(".maps");
```

**使用模式：**

```c
// 获取当前 CPU 的缓冲区
statfunc buf_t *get_buf(int idx)
{
    return bpf_map_lookup_elem(&bufs, &idx);
}

// 每次事件处理使用独立缓冲区
statfunc int init_program_data(program_data_t *p, void *ctx, u32 event_id)
{
    int zero = 0;

    // 获取当前 CPU 的事件数据区
    p->event = bpf_map_lookup_elem(&event_data_map, &zero);
    if (p->event == NULL)
        return 0;

    // 无需锁，每个 CPU 独立
    p->event->context.eventid = event_id;
    return 1;
}
```

### 3.5 Perf Event Array

Perf Event Array 用于高效地将事件从内核发送到用户空间。

**定义示例：**

```c
// 主事件流
struct events {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, 1024);
    __type(key, s32);   // CPU ID
    __type(value, u32); // Perf FD
} events SEC(".maps");

// 控制平面信号
struct signals {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, 1024);
    __type(key, s32);
    __type(value, u32);
} signals SEC(".maps");
```

**内核态提交事件：**

```c
// pkg/ebpf/c/common/buffer.h
statfunc int events_perf_submit(program_data_t *p, long ret)
{
    p->event->context.retval = ret;

    // 计算事件大小
    u32 size = sizeof(event_context_t) + sizeof(u8) + p->event->args_buf.offset;

    // 边界检查
    if (size > MAX_EVENT_SIZE)
        size = MAX_EVENT_SIZE;

    // 发送到当前 CPU 的 perf buffer
    return bpf_perf_event_output(
        p->ctx,
        &events,
        BPF_F_CURRENT_CPU,
        p->event,
        size
    );
}
```

**用户态接收事件（Go）：**

```go
// pkg/ebpf/tracee.go
func (t *Tracee) initBPF() error {
    // 创建事件通道
    t.eventsChannel = make(chan []byte, 1000)
    t.lostEvChannel = make(chan uint64)

    // 初始化 Perf Buffer
    t.eventsPerfMap, err = t.bpfModule.InitPerfBuf(
        "events",
        t.eventsChannel,
        t.lostEvChannel,
        t.config.PerfBufferSize,
    )
    if err != nil {
        return err
    }

    // 开始轮询
    t.eventsPerfMap.Poll(pollTimeout)
    return nil
}

// 处理事件
func (t *Tracee) handleEvents(ctx context.Context) {
    for {
        select {
        case dataRaw := <-t.eventsChannel:
            // 解码并处理事件
            event := t.decodeEvent(dataRaw)
            t.processEvent(event)
        case lost := <-t.lostEvChannel:
            logger.Warnw("Lost events", "count", lost)
        case <-ctx.Done():
            return
        }
    }
}
```

### 3.6 Program Array（尾调用）

Program Array 存储 BPF 程序引用，用于实现尾调用（tail call）。

**定义示例：**

```c
// 尾调用 ID 枚举
enum tail_call_id_e {
    TAIL_VFS_WRITE,
    TAIL_VFS_WRITEV,
    TAIL_SEND_BIN,
    TAIL_SEND_BIN_TP,
    TAIL_KERNEL_WRITE,
    TAIL_SCHED_PROCESS_EXEC_EVENT_SUBMIT,
    // ... 更多尾调用
    MAX_TAIL_CALL
};

// 通用尾调用数组
struct prog_array {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, MAX_TAIL_CALL);
    __type(key, u32);    // 尾调用 ID
    __type(value, u32);  // 程序 FD
} prog_array SEC(".maps");

// 系统调用入口尾调用
struct sys_enter_tails {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, MAX_EVENT_ID);
    __type(key, u32);    // 事件/系统调用 ID
    __type(value, u32);
} sys_enter_tails SEC(".maps");
```

**尾调用使用：**

```c
// 系统调用入口处理
SEC("raw_tracepoint/sys_enter")
int tracepoint__raw_syscalls__sys_enter(struct bpf_raw_tracepoint_args *ctx)
{
    int id = ctx->args[1];  // 系统调用号

    // 32位兼容处理
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (is_compat(task)) {
        u32 *id_64 = bpf_map_lookup_elem(&sys_32_to_64_map, &id);
        if (id_64 == 0)
            return 0;
        id = *id_64;
    }

    // 跳转到对应的系统调用处理程序
    bpf_tail_call(ctx, &sys_enter_init_tail, id);
    return 0;
}
```

**用户态初始化尾调用（Go）：**

```go
// pkg/ebpf/tracee.go
func (t *Tracee) initTailCall(tailCall events.TailCall) error {
    tailCallMapName := tailCall.GetMapName()
    tailCallProgName := tailCall.GetProgName()
    tailCallIndexes := tailCall.GetIndexes()

    // 获取 Map
    bpfMap, err := t.bpfModule.GetMap(tailCallMapName)
    if err != nil {
        return err
    }

    // 获取程序
    bpfProg, err := t.bpfModule.GetProgram(tailCallProgName)
    if err != nil {
        return err
    }

    bpfProgFD := bpfProg.FileDescriptor()

    // 将程序 FD 写入 Map
    for _, index := range tailCallIndexes {
        err := bpfMap.Update(
            unsafe.Pointer(&index),
            unsafe.Pointer(&bpfProgFD),
        )
        if err != nil {
            return err
        }
    }
    return nil
}
```

### 3.7 Map of Maps（嵌套 Maps）

Map of Maps 允许动态创建和切换内部 Maps，Tracee 用于实现过滤器版本化。

**定义示例：**

```c
#define MAX_FILTER_VERSION 64

// 内部 Map 原型
struct uid_filter {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, u32);
    __type(value, eq_t);
} uid_filter SEC(".maps");

// 外部 Map（Map of Maps）
struct uid_filter_version {
    __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
    __uint(max_entries, MAX_FILTER_VERSION);
    __type(key, u16);                    // 版本号
    __array(values, uid_filter_t);       // 内部 Map 类型
} uid_filter_version SEC(".maps");
```

**内核态查找：**

```c
// 获取指定版本的过滤器 Map
statfunc void *get_filter_map(void *outer_map, u16 version)
{
    return bpf_map_lookup_elem(outer_map, &version);
}

// 在过滤器 Map 中查找
statfunc u64 equality_filter_matches(u64 match_if_key_missing,
                                     void *filter_map,
                                     void *key)
{
    u64 equals_in_policies = 0;
    u64 key_used_in_policies = 0;

    if (filter_map) {
        eq_t *equality = bpf_map_lookup_elem(filter_map, key);
        if (equality != NULL) {
            equals_in_policies = equality->equals_in_policies;
            key_used_in_policies = equality->key_used_in_policies;
        }
    }

    return equals_in_policies | (match_if_key_missing & ~key_used_in_policies);
}
```

**用户态动态创建内部 Map（Go）：**

```go
// pkg/policy/ebpf.go
func createNewInnerMap(m *bpf.Module, mapName string, mapVersion uint16) (*bpf.BPFMapLow, error) {
    // 使用原型 Map 的属性
    prototypeMap, err := m.GetMap(mapName)
    if err != nil {
        return nil, err
    }

    info, err := bpf.GetMapInfoByFD(prototypeMap.FileDescriptor())
    if err != nil {
        return nil, err
    }

    // 创建新的内部 Map
    newInnerMap, err := bpf.CreateMap(
        prototypeMap.Type(),
        fmt.Sprintf("%s_%d", mapName, mapVersion),
        prototypeMap.KeySize(),
        prototypeMap.ValueSize(),
        int(prototypeMap.MaxEntries()),
        opts,
    )
    return newInnerMap, err
}

func updateOuterMap(m *bpf.Module, mapName string, mapVersion uint16, innerMap *bpf.BPFMapLow) error {
    outerMap, err := m.GetMap(mapName)
    if err != nil {
        return err
    }

    u16Key := mapVersion
    innerMapFD := uint32(innerMap.FileDescriptor())

    return outerMap.Update(
        unsafe.Pointer(&u16Key),
        unsafe.Pointer(&innerMapFD),
    )
}
```

### 3.8 LPM Trie（最长前缀匹配）

LPM Trie 用于路径前缀/后缀匹配过滤。

**定义示例：**

```c
// 前缀匹配过滤器
struct data_filter_prefix {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 1024);
    __type(key, data_filter_lpm_key_t);
    __type(value, eq_t);
    __uint(map_flags, BPF_F_NO_PREALLOC);  // LPM Trie 需要此标志
} data_filter_prefix SEC(".maps");

// LPM 键结构
typedef struct data_filter_lpm_key {
    u32 prefix_len;                        // 前缀长度（位）
    char str[MAX_DATA_FILTER_STR_SIZE];    // 数据内容
} data_filter_lpm_key_t;
```

### 3.9 Stack Trace Map

Stack Trace Map 自动收集内核/用户栈追踪。

**定义示例：**

```c
#define MAX_STACK_ADDRESSES 1024
#define MAX_STACK_DEPTH 20

typedef __u64 stack_trace_t[MAX_STACK_DEPTH];

struct stack_addresses {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(max_entries, MAX_STACK_ADDRESSES);
    __type(key, u32);
    __type(value, stack_trace_t);
} stack_addresses SEC(".maps");
```

**使用：**

```c
statfunc int events_perf_submit(program_data_t *p, long ret)
{
    // 捕获用户态栈
    if (p->config->options & OPT_CAPTURE_STACK_TRACES) {
        int stack_id = bpf_get_stackid(
            p->ctx,
            &stack_addresses,
            BPF_F_USER_STACK
        );
        if (stack_id >= 0) {
            p->event->context.stack_id = stack_id;
        }
    }
    // ...
}
```

---

## 4. 内核态 Maps 操作

### 4.1 查找操作（bpf_map_lookup_elem）

```c
// 基本查找
void *bpf_map_lookup_elem(struct bpf_map *map, const void *key);

// 示例：查找任务信息
task_info_t *task_info = bpf_map_lookup_elem(&task_info_map, &tid);
if (task_info == NULL) {
    // 处理不存在情况
    return 0;
}
// 使用 task_info...
```

**注意事项：**
- 返回值是指向 Map 值的直接指针
- 必须检查 NULL
- Per-CPU Map 返回当前 CPU 的值
- 指针在程序退出前有效

### 4.2 更新操作（bpf_map_update_elem）

```c
// 更新/插入
long bpf_map_update_elem(struct bpf_map *map, const void *key,
                         const void *value, u64 flags);

// flags 选项：
// BPF_ANY     - 创建或更新
// BPF_NOEXIST - 仅创建（键不存在时）
// BPF_EXIST   - 仅更新（键存在时）

// 示例：更新进程信息
ret = bpf_map_update_elem(&proc_info_map, &child_pid, p_proc_info, BPF_NOEXIST);
if (ret < 0) {
    // 已存在，使用 BPF_ANY 重试或处理错误
}
```

### 4.3 删除操作（bpf_map_delete_elem）

```c
// 删除条目
long bpf_map_delete_elem(struct bpf_map *map, const void *key);

// 示例：进程退出时清理
SEC("raw_tracepoint/sched_process_exit")
int tracepoint__sched__sched_process_exit(...)
{
    // 删除任务信息
    bpf_map_delete_elem(&task_info_map, &p.event->context.task.host_tid);

    // 如果是进程领导者，删除进程信息
    if (group_dead) {
        bpf_map_delete_elem(&proc_info_map, &tgid);
    }
    return 0;
}
```

### 4.4 错误处理与日志

Tracee 使用结构化日志记录 Map 操作失败：

```c
// pkg/ebpf/c/common/logging.h
#define bpf_log_err(id, ret) \
    do { \
        if (ret < 0) { \
            bpf_log(BPF_LOG_LVL_ERROR, id, ret); \
        } \
    } while (0)

// 使用示例
int ret = bpf_map_update_elem(&task_info_map, &tid, &task_info, BPF_ANY);
bpf_log_err(BPF_LOG_ID_MAP_UPDATE_ELEM, ret);
```

---

## 5. 用户态 Maps 访问

### 5.1 获取 Map 引用

```go
// 通过名称获取 Map
bpfMap, err := t.bpfModule.GetMap("config_map")
if err != nil {
    return fmt.Errorf("failed to get map: %w", err)
}
```

### 5.2 更新 Map

```go
// 更新单个条目
cZero := uint32(0)
err := bpfConfigMap.Update(
    unsafe.Pointer(&cZero),   // key
    unsafe.Pointer(&config),  // value
)

// 更新字节数组键
key := make([]byte, 64)
copy(key, symbolName)
err := bpfKsymsMap.Update(
    unsafe.Pointer(&key[0]),
    unsafe.Pointer(&addr),
)
```

### 5.3 查找 Map

```go
// 获取值
value, err := bpfMap.GetValue(unsafe.Pointer(&key))
if err != nil {
    // 处理不存在或错误
}
```

### 5.4 遍历 Map

```go
// 使用迭代器
iter := bpfMap.Iterator()
for iter.Next() {
    key := iter.Key()
    value, err := bpfMap.GetValue(unsafe.Pointer(&key[0]))
    if err != nil {
        continue
    }
    // 处理 key 和 value
}
```

### 5.5 Perf Buffer 初始化

```go
// 创建通道
eventsChannel := make(chan []byte, 1000)
lostChannel := make(chan uint64)

// 初始化 Perf Buffer
perfBuffer, err := bpfModule.InitPerfBuf(
    "events",           // Map 名称
    eventsChannel,      // 数据通道
    lostChannel,        // 丢失事件通道
    bufferSize,         // 缓冲区大小（页数）
)

// 开始轮询
perfBuffer.Poll(300)  // 300ms 超时

// 清理
defer perfBuffer.Close()
```

---

## 6. Maps 架构图

### 6.1 整体数据流

```
                          ┌─────────────────────────────────────────┐
                          │             User Space                   │
                          │                                          │
                          │  ┌──────────┐      ┌──────────────────┐ │
                          │  │  Tracee  │◄────►│ Policy Manager   │ │
                          │  │  (main)  │      │ (filter updates) │ │
                          │  └────┬─────┘      └────────┬─────────┘ │
                          │       │                     │           │
                          │       │ perf_buffer_poll    │ map_update│
                          └───────┼─────────────────────┼───────────┘
                                  │                     │
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━│━━━━━━━━━━━━━━━━━━━━│━━━━━━━━━━━━━━
                                  │                     │
                          ┌───────▼─────────────────────▼───────────┐
                          │            Kernel Space                  │
                          │                                          │
                          │  ┌─────────────────────────────────────┐│
                          │  │           BPF Maps                   ││
                          │  │                                      ││
                          │  │  ┌─────────┐ ┌─────────┐ ┌────────┐ ││
                          │  │  │config   │ │filter   │ │proc/   │ ││
                          │  │  │_map     │ │_version │ │task_   │ ││
                          │  │  │(ARRAY)  │ │(HASH_   │ │info    │ ││
                          │  │  │         │ │OF_MAPS) │ │(LRU)   │ ││
                          │  │  └────┬────┘ └────┬────┘ └───┬────┘ ││
                          │  │       │           │          │      ││
                          │  │  ┌────▼───────────▼──────────▼────┐ ││
                          │  │  │       BPF Programs              │ ││
                          │  │  │  (kprobe, tracepoint, LSM...)   │ ││
                          │  │  └────────────────┬────────────────┘ ││
                          │  │                   │                  ││
                          │  │  ┌────────────────▼────────────────┐ ││
                          │  │  │ events (PERF_EVENT_ARRAY)       │ ││
                          │  │  │ signals (PERF_EVENT_ARRAY)      │ ││
                          │  │  └─────────────────────────────────┘ ││
                          │  └─────────────────────────────────────┘│
                          └─────────────────────────────────────────┘
```

### 6.2 过滤器版本化机制

```
Policy Update Flow:

  User Space                    Kernel Space
 ┌────────────┐               ┌──────────────────────────┐
 │            │  1. Create    │  uid_filter_version      │
 │  Policy    │  new inner    │  (HASH_OF_MAPS)          │
 │  Manager   │  maps         │  ┌────────────────────┐  │
 │            │──────────────►│  │ key=v1 ──► filter_1│  │
 │            │               │  │ key=v2 ──► filter_2│  │
 │            │  2. Populate  │  │   ...              │  │
 │            │  filter data  │  └────────────────────┘  │
 │            │──────────────►│         │                │
 │            │               │         ▼                │
 │            │  3. Update    │  ┌────────────────────┐  │
 │            │  outer map    │  │ Inner Map (v2)     │  │
 │            │──────────────►│  │ ┌────────────────┐ │  │
 │            │               │  │ │uid=1000: eq_t  │ │  │
 │            │  4. Update    │  │ │uid=1001: eq_t  │ │  │
 │            │  config with  │  │ └────────────────┘ │  │
 │            │  new version  │  └────────────────────┘  │
 └────────────┘──────────────►│                          │
                              │  BPF programs use        │
                              │  version from config_map │
                              │  to lookup correct       │
                              │  filter map              │
                              └──────────────────────────┘
```

### 6.3 尾调用链

```
Syscall Processing Flow:

   raw_tracepoint/sys_enter
           │
           ▼
   ┌───────────────────┐
   │ sys_enter_init_   │     sys_enter_init_tail
   │ tail[syscall_id]  │────►(PROG_ARRAY)
   └───────────────────┘           │
           │                       ▼
           │              ┌────────────────┐
           │              │ sys_enter_init │
           │              │ (save args,    │
           │              │  init context) │
           │              └───────┬────────┘
           │                      │
           ▼                      ▼
   ┌───────────────────┐  ┌────────────────────┐
   │ sys_enter_submit_ │  │ sys_enter_submit   │
   │ tail[syscall_id]  │──│ (evaluate filters, │
   └───────────────────┘  │  submit if match)  │
           │              └────────┬───────────┘
           │                       │
           ▼                       ▼
   ┌───────────────────┐  ┌────────────────────┐
   │ sys_enter_tails   │  │ syscall-specific   │
   │ [syscall_id]      │──│ handler            │
   └───────────────────┘  └────────────────────┘
```

---

## 7. Maps 性能考量

### 7.1 Map 类型选择

| 场景 | 推荐类型 | 原因 |
|------|---------|------|
| 固定配置 | ARRAY | 预分配，O(1)访问 |
| 动态键值 | HASH | 灵活键类型 |
| 缓存场景 | LRU_HASH | 自动淘汰，防止溢出 |
| 高并发 | PERCPU_* | 无锁，避免竞争 |
| 事件流 | PERF_EVENT_ARRAY | 高吞吐量 |

### 7.2 容量规划

```c
// Tracee 的容量设计
proc_info_map:    30720  // 支持约3万进程
task_info_map:    10240  // 支持约1万线程
containers_map:   10240  // 支持约1万容器
args_map:         10240  // 系统调用参数
```

**计算内存占用：**
```
Per-CPU Array 内存 = max_entries × value_size × num_cpus
Hash Map 内存 ≈ max_entries × (key_size + value_size + overhead)
LRU Hash 内存 ≈ Hash Map + LRU 链表开销
```

### 7.3 热路径优化

```c
// 避免在热路径上进行不必要的 Map 查找
// 好的做法：缓存查找结果
statfunc int process_event(program_data_t *p)
{
    // 一次查找，多次使用
    config_entry_t *config = bpf_map_lookup_elem(&config_map, &zero);
    if (config == NULL)
        return 0;

    // 使用 config 多次
    if (config->options & OPT_A) { ... }
    if (config->options & OPT_B) { ... }

    return 1;
}

// 避免的做法：重复查找
statfunc int process_event_bad(program_data_t *p)
{
    // 每次都查找，浪费资源
    if (get_config()->options & OPT_A) { ... }  // 查找1
    if (get_config()->options & OPT_B) { ... }  // 查找2
}
```

### 7.4 Per-CPU vs 共享

```
Per-CPU Maps:
  - 优点：无锁、高性能
  - 缺点：内存占用 × CPU数
  - 适用：频繁读写的临时数据

Shared Maps (HASH/ARRAY):
  - 优点：内存效率高、数据一致
  - 缺点：可能有锁竞争
  - 适用：配置、持久状态
```

---

## 8. Maps 内存管理

### 8.1 预分配 vs 动态分配

| 类型 | 分配策略 | 特点 |
|------|---------|------|
| ARRAY | 预分配 | 创建时分配所有内存 |
| HASH | 动态 | 按需分配 |
| LRU_HASH | 动态+LRU | 自动回收 |
| LPM_TRIE | 动态 | 需要 BPF_F_NO_PREALLOC |

### 8.2 Map 生命周期

```go
// 1. 创建（在 BPF 程序加载时）
module.BPFLoadObject()

// 2. 使用（运行时）
bpfMap.Update(...)
bpfMap.Lookup(...)

// 3. 销毁（模块卸载时）
module.Close()  // 自动清理所有 Maps
```

### 8.3 避免内存泄漏

```c
// 确保清理不再需要的条目
// 例如：进程退出时清理相关 Maps
SEC("raw_tracepoint/sched_process_exit")
int handle_exit(...)
{
    u32 tid = get_current_tid();
    u32 tgid = get_current_tgid();

    // 清理任务信息
    bpf_map_delete_elem(&task_info_map, &tid);

    // 如果是最后一个线程，清理进程信息
    if (is_group_dead) {
        bpf_map_delete_elem(&proc_info_map, &tgid);

        // 清理进程树过滤器
        void *inner_map = bpf_map_lookup_elem(&process_tree_map_version, &version);
        if (inner_map)
            bpf_map_delete_elem(inner_map, &tgid);
    }

    return 0;
}
```

---

## 9. 常见问题与调试

### 9.1 Map 查找返回 NULL

**可能原因：**
1. 键不存在
2. Map 未正确初始化
3. 键类型/大小不匹配

**调试方法：**
```c
// 添加日志
task_info_t *ti = bpf_map_lookup_elem(&task_info_map, &tid);
if (ti == NULL) {
    bpf_printk("task_info_map lookup failed for tid=%d", tid);
    return 0;
}
```

### 9.2 Map 更新失败

**可能原因：**
1. Map 已满（非 LRU）
2. 使用了错误的 flags
3. 值大小超限

**调试方法：**
```c
int ret = bpf_map_update_elem(&map, &key, &value, BPF_ANY);
if (ret < 0) {
    bpf_printk("map update failed: %d", ret);
}
```

### 9.3 Perf Buffer 丢失事件

**可能原因：**
1. 缓冲区太小
2. 用户空间处理太慢
3. 事件产生速率太高

**解决方法：**
```go
// 1. 增大缓冲区
config.PerfBufferSize = 256  // 页数

// 2. 优化处理逻辑
go func() {
    for data := range eventsChannel {
        // 异步处理，避免阻塞
        processQueue <- data
    }
}()

// 3. 监控丢失率
go func() {
    for lost := range lostChannel {
        stats.LostEvents.Add(lost)
    }
}()
```

### 9.4 使用 bpftool 调试

```bash
# 列出所有 Maps
sudo bpftool map list

# 查看 Map 内容
sudo bpftool map dump name task_info_map

# 查看 Map 统计
sudo bpftool map show name proc_info_map

# 查看 Perf Buffer 状态
sudo bpftool map show name events
```

### 9.5 Map 类型不支持

某些内核版本不支持特定 Map 类型，Tracee 使用运行时检查：

```go
// pkg/ebpf/tracee.go
func validateMapSupport(bpfMap *bpf.BPFMap) error {
    supported, err := bpf.BPFMapTypeIsSupported(bpfMap.Type())
    if err != nil {
        return err
    }
    if !supported {
        return fmt.Errorf("%w: %s", ErrUnsupportedMapType, bpfMap.Type())
    }

    // 检查内部 Map
    innerMap, err := bpfMap.InnerMapInfo()
    if err != nil {
        return nil  // 没有内部 Map
    }

    supported, err = bpf.BPFMapTypeIsSupported(innerMap.Type)
    if !supported {
        return fmt.Errorf("%w: inner type %s", ErrUnsupportedMapType, innerMap.Type)
    }
    return nil
}
```

---

## 10. 动手练习

### 练习 1：理解 Map 定义

**任务：** 分析 `pkg/ebpf/c/maps.h` 中的 Map 定义

1. 找出所有使用 `BPF_MAP_TYPE_LRU_HASH` 的 Maps
2. 解释为什么 `proc_info_map` 使用 LRU 而不是普通 HASH
3. 计算 `task_info_map` 在 8 核系统上的理论最大内存占用

**参考答案：**
```c
// LRU Hash Maps:
// - proc_info_map (30720 entries)
// - task_info_map (10240 entries)
// - fd_arg_path_map (1024 entries)
// - bpf_attach_map (1024 entries)
// - file_modification_map (10240 entries)
// - io_file_path_cache_map (5 entries)
// - elf_files_map (64 entries)
// - syscall_source_map (4096 entries)

// 使用 LRU 的原因：
// 1. 进程数量动态变化，难以预估最大值
// 2. 自动淘汰不活跃进程，避免内存溢出
// 3. 保证热点进程始终在缓存中
```

### 练习 2：跟踪事件流

**任务：** 使用 bpftool 观察事件流

```bash
# 1. 启动 Tracee
sudo tracee --events openat

# 2. 在另一个终端，查看 events Map
sudo bpftool map show name events

# 3. 观察 Perf Buffer 状态
sudo bpftool map dump name events

# 4. 触发事件
cat /etc/passwd

# 5. 观察事件计数变化
```

### 练习 3：实现简单过滤器

**任务：** 理解过滤器 Map 的工作原理

1. 阅读 `pkg/ebpf/c/common/filtering.h` 中的 `equality_filter_matches` 函数
2. 画出以下场景的位图计算过程：
   - Policy 1: `comm=bash`
   - Policy 2: `comm!=bash`
   - 当前命令: `bash`

**思考：**
```
equals_in_policies   = ?
key_used_in_policies = ?
match_if_key_missing = ?
result               = ?
```

### 练习 4：Map 版本化分析

**任务：** 分析 Map of Maps 的使用

1. 在 `pkg/policy/ebpf.go` 中找到 `createNewInnerMap` 函数
2. 解释为什么 Tracee 需要过滤器版本化
3. 描述版本切换的原子性如何保证

### 练习 5：性能分析

**任务：** 分析 Map 操作的性能影响

1. 在 `pkg/ebpf/c/tracee.bpf.c` 中统计 `bpf_map_lookup_elem` 的调用次数
2. 找出调用最频繁的 Map
3. 提出一个优化建议

---

## 11. 核心代码走读

### 11.1 Maps 定义文件

**文件：** `/home/work/tracee_study/pkg/ebpf/c/maps.h`

这是 Tracee 所有 BPF Maps 的定义文件，包含：
- 40+ 个 Map 定义
- 尾调用 ID 枚举
- Map 类型别名

**关键结构：**
```c
// 尾调用 ID
enum tail_call_id_e {
    TAIL_VFS_WRITE,
    TAIL_VFS_WRITEV,
    // ...
    MAX_TAIL_CALL
};

// 配置 Map
struct config_map { ... } config_map SEC(".maps");

// 过滤器 Maps（版本化）
struct uid_filter { ... } uid_filter SEC(".maps");
struct uid_filter_version { ... } uid_filter_version SEC(".maps");
```

### 11.2 Map 操作辅助函数

**文件：** `/home/work/tracee_study/pkg/ebpf/c/common/context.h`

```c
// 获取或初始化进程信息
statfunc proc_info_t *get_proc_info(u32 pid)
{
    return bpf_map_lookup_elem(&proc_info_map, &pid);
}

// 初始化程序数据
statfunc bool init_program_data(program_data_t *p, void *ctx, u32 event_id)
{
    int zero = 0;

    p->event = bpf_map_lookup_elem(&event_data_map, &zero);
    if (p->event == NULL)
        return false;

    p->config = bpf_map_lookup_elem(&config_map, &zero);
    if (p->config == NULL)
        return false;

    // ...
    return true;
}
```

### 11.3 用户态 Map 操作

**文件：** `/home/work/tracee_study/pkg/ebpf/tracee.go`

```go
// 填充 BPF Maps
func (t *Tracee) populateBPFMaps() error {
    // 32位到64位系统调用映射
    sys32to64BPFMap, err := t.bpfModule.GetMap("sys_32_to_64_map")
    // ...

    // 更新 kallsyms
    err = t.UpdateKallsyms()
    // ...

    // 初始化配置
    bpfKConfigMap, err := t.bpfModule.GetMap("kconfig_map")
    // ...

    // 填充过滤器
    err = t.populateFilterMaps(false)
    // ...

    // 初始化尾调用
    for _, tailCall := range tailCalls {
        err := t.initTailCall(tailCall)
    }
}
```

### 11.4 Policy Map 更新

**文件：** `/home/work/tracee_study/pkg/policy/ebpf.go`

```go
// 创建版本化过滤器 Map
func createNewInnerMap(m *bpf.Module, mapName string, mapVersion uint16) (*bpf.BPFMapLow, error) {
    prototypeMap, err := m.GetMap(mapName)
    // ...

    newInnerMap, err := bpf.CreateMap(
        prototypeMap.Type(),
        fmt.Sprintf("%s_%d", mapName, mapVersion),
        prototypeMap.KeySize(),
        prototypeMap.ValueSize(),
        int(prototypeMap.MaxEntries()),
        opts,
    )
    return newInnerMap, nil
}

// 更新外部 Map
func updateOuterMap(m *bpf.Module, mapName string, mapVersion uint16, innerMap *bpf.BPFMapLow) error {
    outerMap, err := m.GetMap(mapName)
    // ...

    return outerMap.Update(
        unsafe.Pointer(&u16Key),
        unsafe.Pointer(&innerMapFD),
    )
}
```

---

## 12. 总结

### 关键要点

1. **BPF Maps 是核心通信机制**
   - 内核态与用户态的桥梁
   - 程序间状态共享

2. **选择正确的 Map 类型**
   - HASH: 动态键值
   - ARRAY: 固定索引
   - LRU_HASH: 缓存场景
   - PERCPU: 高并发

3. **版本化支持热更新**
   - Map of Maps 实现
   - 原子切换过滤规则

4. **性能优化关键**
   - 减少热路径查找
   - 使用 Per-CPU 避免锁
   - 合理设置容量

5. **正确处理生命周期**
   - 及时清理不需要的条目
   - 监控内存使用

### 进阶学习资源

- [BPF and XDP Reference Guide](https://docs.cilium.io/en/stable/bpf/)
- [Linux Kernel BPF Documentation](https://www.kernel.org/doc/html/latest/bpf/)
- [libbpfgo Documentation](https://github.com/aquasecurity/libbpfgo)
- [Tracee Source Code](https://github.com/aquasecurity/tracee)

---

## 附录：Maps 速查表

### A. Map 类型速查

| 类型 | 用途 | 键 | 值 | 特点 |
|------|-----|----|----|-----|
| HASH | 通用键值 | 任意 | 任意 | 动态 |
| ARRAY | 索引访问 | u32 | 任意 | 预分配 |
| LRU_HASH | 缓存 | 任意 | 任意 | 自动淘汰 |
| PERCPU_ARRAY | 并发 | u32 | 任意 | 无锁 |
| PERF_EVENT_ARRAY | 事件流 | CPU ID | FD | 环形 |
| PROG_ARRAY | 尾调用 | u32 | 程序FD | 跳转 |
| HASH_OF_MAPS | 嵌套 | 任意 | Map FD | 动态 |
| LPM_TRIE | 前缀匹配 | 特殊 | 任意 | Trie |
| STACK_TRACE | 栈追踪 | u32 | 地址数组 | 特殊 |

### B. 常用 Helper 函数

| 函数 | 用途 | 返回 |
|------|-----|------|
| `bpf_map_lookup_elem` | 查找 | 值指针或 NULL |
| `bpf_map_update_elem` | 更新 | 0 或错误码 |
| `bpf_map_delete_elem` | 删除 | 0 或错误码 |
| `bpf_perf_event_output` | 发送事件 | 0 或错误码 |
| `bpf_tail_call` | 尾调用 | 不返回（成功时） |
| `bpf_get_stackid` | 获取栈 | 栈 ID 或负数 |

### C. 错误码参考

| 错误码 | 含义 |
|-------|-----|
| -EINVAL | 无效参数 |
| -ENOENT | 键不存在 |
| -E2BIG | Map 已满 |
| -EEXIST | 键已存在（BPF_NOEXIST） |
| -EPERM | 权限不足 |
| -ENOMEM | 内存不足 |
