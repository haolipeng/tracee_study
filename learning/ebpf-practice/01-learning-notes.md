# eBPF 学习注意事项

本文档总结了学习 eBPF 内核态编程过程中的重要注意事项和常见陷阱。

---

## 一、环境准备注意事项

### 1. 内核版本要求

```bash
# 检查内核版本
uname -r

# 最低要求 5.4，推荐 5.15+
# 原因：不同版本支持的 eBPF 特性不同
```

| 特性 | 最低内核版本 |
|------|-------------|
| BTF/CO-RE | 5.2 |
| Ring Buffer | 5.8 |
| BPF LSM | 5.7 |
| bpf_d_path | 5.9 |

### 2. 必须启用 BTF

```bash
# 验证 BTF 可用
ls /sys/kernel/btf/vmlinux

# 如果不存在，需要重新编译内核或换发行版
# Ubuntu 20.04+ / Fedora 31+ 默认启用
```

### 3. 权限问题

```bash
# eBPF 程序必须以 root 运行
sudo ./hello_exec

# 或者使用 CAP_BPF + CAP_PERFMON (内核 5.8+)
sudo setcap cap_bpf,cap_perfmon+ep ./hello_exec
```

---

## 二、编码注意事项

### 1. 验证器限制 (最常见的坑)

**循环必须有界：**

```c
// ❌ 错误：无界循环
for (int i = 0; i < n; i++) { ... }

// ✅ 正确：有界循环 + pragma
#pragma unroll
for (int i = 0; i < 16; i++) { ... }  // 常量上限
```

**边界检查必须显式：**

```c
// ❌ 错误：验证器无法证明边界
char buf[256];
bpf_probe_read(buf, len, src);  // len 可能 > 256

// ✅ 正确：显式边界检查
if (len > sizeof(buf))
    len = sizeof(buf);
bpf_probe_read(buf, len, src);
```

### 2. 栈空间限制 (512 字节)

```c
// ❌ 错误：栈上分配大数组
char path[4096];  // 超出栈限制

// ✅ 正确：使用 per-CPU map
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, char[4096]);
} heap SEC(".maps");

// 使用
u32 zero = 0;
char *path = bpf_map_lookup_elem(&heap, &zero);
```

### 3. 内存访问必须安全

```c
// ❌ 错误：直接解引用内核指针
char *name = task->comm;

// ✅ 正确：使用 CO-RE 宏
char name[16];
BPF_CORE_READ_STR_INTO(&name, task, comm);

// 或使用 bpf_probe_read_kernel
bpf_probe_read_kernel_str(name, sizeof(name),
                          BPF_CORE_READ(task, comm));
```

### 4. Map 查找返回值检查

```c
// ❌ 错误：不检查返回值
u64 *count = bpf_map_lookup_elem(&map, &key);
*count += 1;  // 可能空指针

// ✅ 正确：始终检查
u64 *count = bpf_map_lookup_elem(&map, &key);
if (count)
    *count += 1;
```

### 5. 字符串处理

```c
// ❌ 错误：使用标准库函数
strlen(str);  // 不可用
strcpy(dst, src);  // 不可用

// ✅ 正确：使用 BPF helper
bpf_probe_read_kernel_str(dst, size, src);
```

### 6. 指针算术限制

```c
// ❌ 错误：复杂指针运算
char *p = buf + offset * stride;

// ✅ 正确：简单偏移
char *p = buf + offset;  // offset 必须有边界检查
```

---

## 三、调试技巧

### 1. 使用 bpf_printk 调试

```c
// 内核态
bpf_printk("pid=%d, syscall=%d\n", pid, syscall_id);

// 查看输出
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

> **注意**：生产环境移除 bpf_printk，有性能开销

### 2. 验证器错误解读

| 错误信息 | 含义 | 解决方案 |
|---------|------|---------|
| `invalid mem access` | 边界检查不足 | 添加显式边界检查 |
| `back-edge from insn` | 循环未展开 | 使用 `#pragma unroll` |
| `R1 type=map_value expected=...` | 忘记检查 map_lookup 返回值 | 添加 NULL 检查 |
| `math between X and Y` | 指针算术错误 | 简化指针运算 |
| `unreachable insn` | 死代码 | 检查控制流 |
| `invalid stack off` | 栈越界 | 减少栈使用 |

### 3. 使用 bpftool 检查

```bash
# 查看加载的程序
sudo bpftool prog show

# 查看程序指令
sudo bpftool prog dump xlated id <ID>

# 查看 JIT 编译后的汇编
sudo bpftool prog dump jited id <ID>

# 查看 map 内容
sudo bpftool map dump name my_map

# 查看程序统计
sudo bpftool prog show id <ID> --json | jq '.run_cnt'
```

### 4. 查看内核日志

```bash
# 验证器详细错误
sudo dmesg | tail -100

# 实时查看
sudo dmesg -w
```

---

## 四、性能注意事项

### 1. 减少事件量

```c
// ❌ 不好：追踪所有系统调用
SEC("raw_tracepoint/sys_enter")
int trace_all(...) { ... }

// ✅ 更好：早期过滤
SEC("raw_tracepoint/sys_enter")
int trace_filtered(struct bpf_raw_tracepoint_args *ctx)
{
    u32 syscall_id = ctx->args[1];

    // 只关心特定系统调用
    if (syscall_id != __NR_execve && syscall_id != __NR_open)
        return 0;

    // ... 处理逻辑
}
```

### 2. 使用合适的 Map 类型

| 场景 | 推荐 Map 类型 | 原因 |
|------|--------------|------|
| 固定键集合 | HASH | 精确查找 |
| 动态键，需要淘汰 | LRU_HASH | 自动清理旧条目 |
| 高并发更新 | PERCPU_HASH | 无锁，每 CPU 独立 |
| 连续整数键 | ARRAY | O(1) 访问 |
| 内核 5.8+ 事件输出 | RINGBUF | 比 PERF_ARRAY 更高效 |
| 前缀匹配 | LPM_TRIE | IP 地址匹配 |

### 3. 避免热路径上的复杂操作

```c
// ❌ 不好：每次都计算路径
SEC("kprobe/vfs_read")
int trace(...) {
    get_full_path(file, buf, 4096);  // 昂贵操作
    ...
}

// ✅ 更好：只在需要时计算
SEC("kprobe/vfs_read")
int trace(...) {
    // 先检查是否需要追踪
    if (!should_trace(file))
        return 0;

    // 只在必要时执行昂贵操作
    get_full_path(file, buf, 4096);
    ...
}
```

### 4. Tail Call 优化

```c
// 使用 tail call 拆分大程序
// 1. 减少单个程序复杂度
// 2. 绕过验证器限制
// 3. 实现动态分发

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 10);
    __type(key, u32);
    __type(value, u32);
} progs SEC(".maps");

SEC("raw_tracepoint/sys_enter")
int dispatcher(void *ctx) {
    u32 syscall_id = ...;
    bpf_tail_call(ctx, &progs, syscall_id);
    return 0;  // tail call 失败时的默认处理
}
```

---

## 五、学习顺序建议

### 推荐顺序

```
1. Demo 1 (hello-exec)      ← 必须先掌握基础
   学习：tracepoint, perf buffer, helper 函数
   ↓
2. Demo 2 (syscall-counter) ← 掌握 Map 操作
   学习：raw_tracepoint, Hash Map, 原子操作
   ↓
3. Demo 3 (process-tree)    ← 理解 CO-RE
   学习：sched tracepoint, BPF_CORE_READ, task_struct
   ↓
4. Demo 4 (file-monitor)    ← kprobe 模式
   学习：kprobe/kretprobe, args_map 模式
   ↓
5-7 (网络/安全)             ← 可根据兴趣选择
```

### 每个 Demo 的学习步骤

1. **先读 README.md** - 了解学习目标和核心概念
2. **读 BPF 代码 (.bpf.c)** - 理解内核态实现
3. **读用户态代码 (.c)** - 理解数据处理和展示
4. **编译运行** - 验证功能，观察输出
5. **对照 Tracee 源码** - 理解生产级实现的差异
6. **做练习题** - 巩固和扩展知识
7. **阅读相关 Git Commit** - 学习 bug 修复和优化技巧

---

## 六、常见错误排查

### 1. 编译错误

```bash
# "vmlinux.h not found"
cd demos && make vmlinux  # 重新生成

# "unknown type name 'xxx'"
# 检查 vmlinux.h 是否包含该类型
grep "struct xxx" demos/common/vmlinux.h

# "undefined reference to 'xxx'"
# 检查链接选项
pkg-config --libs libbpf
```

### 2. 加载失败

```bash
# "Operation not permitted"
sudo ./program  # 需要 root 权限

# "Invalid argument"
# 通常是验证器错误，查看详细信息
sudo cat /sys/kernel/debug/tracing/trace_pipe &
sudo dmesg | tail -50

# "Program too large"
# 程序超过指令限制 (100万条)
# 解决：拆分程序，使用 tail call
```

### 3. 没有事件输出

检查清单：

```
□ 程序是否成功加载？ (bpftool prog show)
□ 程序是否成功附加？ (检查 attach 返回值)
□ Hook 点是否正确？ (检查内核是否有该函数)
□ 事件过滤是否太严格？ (暂时移除过滤逻辑)
□ perf buffer 是否正确设置？ (检查 map fd)
□ 用户态是否在正确 poll？ (检查 poll 超时)
□ 是否有触发事件的操作？ (运行一些命令触发)
```

### 4. 事件丢失

```c
// 用户态检查丢失事件
static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
    fprintf(stderr, "Lost %llu events on CPU #%d!\n", lost_cnt, cpu);
}

// 解决方案：
// 1. 增加 buffer 大小
pb = perf_buffer__new(map_fd, 64, ...);  // 64 页而不是 8 页

// 2. 减少事件量（更严格的过滤）

// 3. 使用 Ring Buffer（内核 5.8+，更高效）
```

---

## 七、与 Tracee 代码对比学习

### Demo 与 Tracee 的差异

| 方面 | Demo (简化版) | Tracee (生产级) |
|------|--------------|-----------------|
| 路径解析 | 只向上遍历 5 层 | 完整 dentry 遍历 |
| 事件过滤 | 无过滤 | 多维度策略过滤 |
| 错误处理 | 简单返回 0 | 详细日志和错误恢复 |
| 容器支持 | 无 | 完整 namespace 检测 |
| 32位兼容 | 无 | 32/64位系统调用转换 |
| 性能优化 | 基础 | tail call, per-CPU buffer |

### 建议的对比阅读

每完成一个 Demo 后，对照阅读 Tracee 对应代码：

| Demo | Tracee 文件 | 行号 | 关注点 |
|------|------------|------|--------|
| 1 | tracee.bpf.c | 364-482 | 参数捕获完整性 |
| 2 | tracee.bpf.c | 45-60 | tail call 分发 |
| 3 | tracee.bpf.c | 602-757 | 容器检测逻辑 |
| 4 | tracee.bpf.c | 3325-3398 | magic write 检测 |
| 5 | tracee.bpf.c | 2696-2793 | 协议解析 |
| 6 | tracee.bpf.c | 2530-2549 | 审计过滤 |
| 7 | tracee.bpf.c | 3680-3779 | JIT 识别 |

---

## 八、进阶学习资源

### 官方文档

- [Kernel BPF Documentation](https://docs.kernel.org/bpf/)
- [libbpf Documentation](https://libbpf.readthedocs.io/)
- [libbpf API](https://libbpf.readthedocs.io/en/latest/api.html)

### 深入文章

- [BPF CO-RE Reference Guide](https://nakryiko.com/posts/bpf-core-reference-guide/) - CO-RE 权威指南
- [BPF Tips & Tricks](https://nakryiko.com/posts/bpf-tips-printk/) - 调试技巧
- [BPF Portability](https://nakryiko.com/posts/bpf-portability-and-co-re/) - 可移植性

### 实践项目

- [libbpf-bootstrap](https://github.com/libbpf/libbpf-bootstrap) - 项目模板
- [bcc libbpf-tools](https://github.com/iovisor/bcc/tree/master/libbpf-tools) - 实用工具参考
- [Tracee](https://github.com/aquasecurity/tracee) - 本学习项目的源码

### 书籍

- "BPF Performance Tools" by Brendan Gregg
- "Learning eBPF" by Liz Rice

---

## 九、检查清单

### 开始编码前

- [ ] 内核版本满足要求
- [ ] BTF 可用
- [ ] 开发工具安装完成
- [ ] vmlinux.h 已生成

### 编写 BPF 代码时

- [ ] 循环有常量上限
- [ ] 所有指针访问有边界检查
- [ ] Map 查找结果有 NULL 检查
- [ ] 栈使用不超过 512 字节
- [ ] 使用 BPF_CORE_READ 读取内核结构

### 提交前

- [ ] 移除 bpf_printk 调试语句
- [ ] 测试边界情况
- [ ] 检查内存泄漏（Map 条目清理）
- [ ] 验证在目标内核版本运行正常
