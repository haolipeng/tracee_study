# Demo 3: Process Tree - 进程生命周期监控

## 学习目标

1. **sched 类 Raw Tracepoint**
   - sched_process_fork
   - sched_process_exec
   - sched_process_exit

2. **BPF_CORE_READ 宏**
   - 安全读取内核数据结构
   - CO-RE (Compile Once, Run Everywhere)

3. **task_struct 结构**
   - pid vs tgid
   - 父子进程关系
   - 启动时间

4. **Git Commit `5a727b30`**
   - 线程栈识别算法改进

## 编译和运行

```bash
cd demos
make demo3
sudo ./03-process-tree/process_tree
```

## 预期输出

```
=============================================================
Demo 3: Process Lifecycle Monitor (Fork/Exec/Exit)
=============================================================
Tracing process events... Press Ctrl+C to exit.

TIME     TYPE   COMM             DETAILS
-------------------------------------------------------------
10:30:15 [FORK] bash             PID=1234    PPID=1200   -> child PID=1235
10:30:15 [EXEC] bash             PID=1235    PPID=1234   -> /usr/bin/ls
10:30:15 [EXIT] ls               PID=1235    PPID=1234   exit_code=0
```

## 核心代码解析

### 1. task_struct 读取

```c
// PID vs TGID 区别
// - tgid: Thread Group ID = 用户空间的 PID
// - pid:  Process ID = 用户空间的 TID

statfunc u32 get_task_pid(struct task_struct *task)
{
    return BPF_CORE_READ(task, tgid);  // 返回用户空间 PID
}

statfunc u32 get_task_tid(struct task_struct *task)
{
    return BPF_CORE_READ(task, pid);   // 返回用户空间 TID
}
```

### 2. BPF_CORE_READ 链式读取

```c
// 读取 task->real_parent->tgid
statfunc u32 get_task_ppid(struct task_struct *task)
{
    struct task_struct *parent = BPF_CORE_READ(task, real_parent);
    return BPF_CORE_READ(parent, tgid);
}

// 等价于:
// return task->real_parent->tgid;
// 但 BPF_CORE_READ 处理了偏移和 CO-RE 重定位
```

### 3. sched_process_fork 参数

```c
SEC("raw_tracepoint/sched_process_fork")
int trace_fork(struct bpf_raw_tracepoint_args *ctx)
{
    // ctx->args[0] = parent task_struct
    // ctx->args[1] = child task_struct
    struct task_struct *parent = (struct task_struct *)ctx->args[0];
    struct task_struct *child = (struct task_struct *)ctx->args[1];
}
```

## Git Commit `5a727b30` 学习

**问题**：通过 VMA 识别线程栈不可靠

**原因**：
- VMA (Virtual Memory Area) 可能被分割或合并
- 搜索的 VMA 可能与线程栈 VMA 不对齐

**修复方案**：改用地址范围判断

```c
// 修复前：VMA 匹配
statfunc bool vma_is_thread_stack(task_info_t *ti, struct vm_area_struct *vma)
{
    address_range_t *stack = &ti->stack;
    return BPF_CORE_READ(vma, vm_start) >= stack->start &&
           BPF_CORE_READ(vma, vm_end) <= stack->end;
}

// 修复后：地址范围判断
statfunc bool address_in_thread_stack(task_info_t *ti, u64 address)
{
    address_range_t *stack = &ti->stack;
    if (stack->start == 0 && stack->end == 0)
        return false;
    return address >= stack->start && address <= stack->end;
}
```

**教训**：简洁直观的算法往往更可靠

## 与 Tracee 对比

| 特性 | Demo | Tracee |
|------|------|--------|
| Fork 追踪 | 基础 | + 进程树过滤 |
| Exec 追踪 | filename | + argv + envp |
| Exit 追踪 | exit_code | + 信号处理 |
| 容器感知 | 无 | mnt_ns 检测 |

**Tracee 参考**:
- `pkg/ebpf/c/tracee.bpf.c:602-757`
- `pkg/ebpf/c/common/task.h`

## 练习题

1. **进程树构建**：在用户态实现简单的进程树数据结构

2. **容器检测**：添加 mount namespace ID 检测，识别容器进程

3. **短命进程追踪**：统计存活时间小于1秒的进程

## 常见问题

### Q: 为什么用 real_parent 而不是 parent?

A: `real_parent` 是真正的父进程，`parent` 可能因为 ptrace 而指向调试器。
   Tracee 使用 `real_parent` 获取准确的父子关系。

### Q: exit_code 为什么要右移 8 位?

A: Linux 的 exit_code 格式:
   - 低 8 位: 信号编号 (如果被信号杀死)
   - 高 8 位: 退出状态码 (exit() 的参数)

## 下一步

继续 [Demo 4: file-monitor](../04-file-monitor/README.md)
学习 kprobe 追踪文件系统操作。
