# Demo 2: Syscall Counter - 系统调用计数器

## 学习目标

通过这个 Demo，你将学习：

1. **Raw Tracepoint 的使用**
   - 与 tracepoint 的区别
   - 参数访问方式

2. **BPF Hash Map 操作**
   - 定义和初始化
   - 查找、更新、遍历

3. **原子操作**
   - `__sync_fetch_and_add()` 的使用
   - 多 CPU 并发安全

4. **Tracee 内联汇编技巧**
   - `update_min` 宏
   - Git Commit `9f591d33` 的 bug 修复

## 文件说明

```
02-syscall-counter/
├── syscall_counter.bpf.c   # eBPF 内核态程序
├── syscall_counter.c       # 用户态程序
└── README.md               # 本文件
```

## 编译和运行

```bash
cd demos
make demo2
sudo ./02-syscall-counter/syscall_counter
```

## 预期输出

```
=============================================================
Demo 2: System Call Counter (Top 15)
=============================================================
SYSCALL# | NAME                 | COUNT
-------------------------------------------------------------
202      | futex                | 123456
0        | read                 | 98765
1        | write                | 87654
232      | epoll_wait           | 76543
...
-------------------------------------------------------------
Total syscalls (top 15): 500000
```

## 核心代码解析

### 1. Raw Tracepoint vs Tracepoint

```c
// Raw Tracepoint - 更底层，性能更好
SEC("raw_tracepoint/sys_enter")
int trace_sys_enter(struct bpf_raw_tracepoint_args *ctx)
{
    u32 syscall_id = (u32)ctx->args[1];
    // ...
}

// 普通 Tracepoint - 有结构化参数
SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct execve_args *ctx)
{
    const char *filename = ctx->filename;
    // ...
}
```

**区别**：
- Raw Tracepoint 参数是 `void *`，需要手动解析
- Tracepoint 提供结构化参数
- Raw Tracepoint 开销更小

### 2. Hash Map 操作

```c
// 定义
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 512);
    __type(key, u32);
    __type(value, u64);
} syscall_count_map SEC(".maps");

// 查找
u64 *count = bpf_map_lookup_elem(&syscall_count_map, &syscall_id);

// 更新
bpf_map_update_elem(&syscall_count_map, &syscall_id, &value, BPF_ANY);
```

### 3. 原子操作

```c
// 原子递增 - 多 CPU 安全
__sync_fetch_and_add(count, 1);
```

### 4. Git Commit `9f591d33` 学习

**问题**：内联汇编宏缺少输出约束

```c
// 修复前 (有 bug)
#define update_min(var, max_val)                                  \
    asm volatile("if %[v] <= %[m] goto +1;\n"                     \
                 "%[v] = %[m];\n"                                 \
                 :                          /* 空输出约束! */      \
                 : [v] "r"(var), [m] "r"(max_val))

// 修复后
#define update_min(var, max_val)                                  \
    asm volatile("if %[v] <= %[m] goto +1;\n"                     \
                 "%[v] = %[m];\n"                                 \
                 : [v] "+r"(var)           /* +r 表示读写 */       \
                 : [m] "r"(max_val))
```

**教训**：
- `"r"` 表示只读输入
- `"+r"` 表示读写（同时是输入和输出）
- 没有正确的输出约束，编译器优化可能导致意外行为

## 与 Tracee 代码对比

| 特性 | Demo | Tracee |
|------|------|--------|
| 追踪点 | raw_tracepoint | raw_tracepoint |
| Map 类型 | HASH | LRU_HASH |
| 统计粒度 | 全局 | 可按进程/容器 |
| 过滤 | 无 | 多维度 |

**Tracee 参考代码**：
- `pkg/ebpf/c/tracee.bpf.c:45-60` (sys_enter)
- `pkg/ebpf/c/common/common.h` (update_min 宏)

## 练习题

1. **扩展练习**：实现按进程统计（使用 `proc_syscall_map`）

2. **性能优化**：使用 `BPF_MAP_TYPE_PERCPU_HASH` 避免原子操作

3. **可视化**：输出为 CSV 格式，用 Python 绘制系统调用分布图

## Map 类型选择指南

| 类型 | 特点 | 适用场景 |
|------|------|----------|
| HASH | 精确查找 | 固定键集合 |
| LRU_HASH | 自动淘汰 | 动态键集合 |
| PERCPU_HASH | 无锁 | 高并发更新 |
| ARRAY | O(1) 访问 | 连续整数键 |

## 常见问题

### Q: 为什么使用 raw_tracepoint 而不是 kprobe？

A: raw_tracepoint 是内核稳定的接口，不会因内核版本变化而失效。
   kprobe 附加到具体函数，可能因函数重命名/内联而失败。

### Q: BPF_ANY vs BPF_NOEXIST vs BPF_EXIST？

A:
- `BPF_ANY`: 无论是否存在都更新
- `BPF_NOEXIST`: 只有不存在时才插入
- `BPF_EXIST`: 只有存在时才更新

## 下一步

学习完本 Demo 后，继续 [Demo 3: process-tree](../03-process-tree/README.md)
学习如何追踪进程生命周期和构建进程树。
