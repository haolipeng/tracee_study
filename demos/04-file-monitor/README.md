# Demo 4: File Monitor - 文件系统监控

## 学习目标

1. **kprobe/kretprobe 使用**
   - 追踪内核函数进入和返回
   - 获取函数参数和返回值

2. **args_map 模式**
   - 在 entry/return 间传递参数
   - Tracee 核心设计模式

3. **文件路径解析**
   - dentry 结构遍历
   - 路径字符串构建

4. **Git Commit `afb503db`**
   - 位操作 bug 修复

## 编译和运行

```bash
cd demos
make demo4
sudo ./04-file-monitor/file_monitor
```

## 核心代码解析

### 1. kprobe/kretprobe 模式

```c
// Entry: 保存参数
SEC("kprobe/vfs_write")
int BPF_KPROBE(trace_vfs_write_entry, struct file *file, ...)
{
    u32 tid = bpf_get_current_pid_tgid();
    struct vfs_args args = { .file = file, ... };
    bpf_map_update_elem(&args_map, &tid, &args, BPF_ANY);
    return 0;
}

// Return: 获取参数和返回值
SEC("kretprobe/vfs_write")
int BPF_KRETPROBE(trace_vfs_write_return, ssize_t ret)
{
    u32 tid = bpf_get_current_pid_tgid();
    struct vfs_args *args = bpf_map_lookup_elem(&args_map, &tid);
    // 使用 args 和 ret
}
```

### 2. Git Commit `afb503db` 学习

**问题**：save_bytes_to_buf 中的位操作 bug

```c
// 修复前：位操作计算错误
bpf_probe_read(&buf[offset], size & (MAX_SIZE - 1), ptr);
// 当 MAX_SIZE = 256, size = 300 时:
// 300 & 255 = 44  (错误!)

// 修复后：显式条件判断
size_t read_size = size;
if (read_size >= MAX_SIZE)
    read_size = MAX_SIZE - 1;
bpf_probe_read(&buf[offset], read_size, ptr);
```

**教训**：位操作技巧可能引入微妙 bug，显式判断更安全

## 与 Tracee 对比

| 特性 | Demo | Tracee |
|------|------|--------|
| 路径解析 | 简化版 | 完整 dentry 遍历 |
| Magic 检测 | 无 | 检测 ELF/脚本头 |
| 过滤 | 无 | 路径/进程过滤 |

**Tracee 参考**: `pkg/ebpf/c/tracee.bpf.c:3325-3398`

## 练习题

1. **Magic Write 检测**：读取写入内容的前 16 字节，检测 ELF 头

2. **路径过滤**：只监控特定目录（如 /tmp）

3. **大文件检测**：标记超过 1MB 的写操作
