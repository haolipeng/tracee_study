// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//
// Demo 4: file_monitor - File System Operations Monitor
//
// 学习目标:
//   1. 使用 kprobe/kretprobe 追踪 VFS 函数
//   2. 掌握 args_map 模式 (在 entry/return 间传递参数)
//   3. 学习文件路径解析
//   4. 理解 Tracee 的 magic write 检测
//
// 参考 Tracee 代码:
//   - pkg/ebpf/c/tracee.bpf.c:3325-3398 (vfs_write/read)
//   - pkg/ebpf/c/common/filesystem.h
//
// Git Commit 学习:
//   - afb503db: 位操作 bug 修复 (save_bytes_to_buf)

#include "common.h"

// ============================================================================
// Constants
// ============================================================================

#define MAX_PATH_SIZE 256
#define FILE_MAGIC_SIZE 16

// 文件操作类型
enum file_op_type {
    FILE_OP_READ  = 1,
    FILE_OP_WRITE = 2,
    FILE_OP_OPEN  = 3,
};

// ============================================================================
// Event Structure
// ============================================================================

struct file_event {
    u64 timestamp;
    u32 pid;
    u32 tid;
    u32 uid;
    char comm[TASK_COMM_LEN];

    u32 op_type;                     // read/write/open
    char path[MAX_PATH_SIZE];        // 文件路径
    u64 offset;                      // 文件偏移
    size_t count;                    // 读写字节数
    ssize_t ret;                     // 返回值

    u8 magic[FILE_MAGIC_SIZE];       // 文件头 (用于 magic write 检测)
};

// ============================================================================
// BPF Maps
// ============================================================================

// Perf buffer for events
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
} events SEC(".maps");

// args_map: 在 kprobe entry 和 kretprobe 间传递参数
// 这是 Tracee 的核心模式
// Key: tid
// Value: 保存的参数
struct vfs_args {
    struct file *file;
    loff_t *pos;
    size_t count;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);
    __type(value, struct vfs_args);
} args_map SEC(".maps");

// ============================================================================
// Helper Functions
// ============================================================================

// 获取文件路径
// 参考: Tracee pkg/ebpf/c/common/filesystem.h get_path_str
// 简化版: 只读取 dentry->d_name
statfunc int get_file_path(struct file *file, char *buf, size_t size)
{
    // 获取 dentry
    struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
    if (!dentry)
        return -1;

    // 读取文件名 (d_name.name 是内核指针)
    struct qstr d_name = BPF_CORE_READ(dentry, d_name);
    bpf_probe_read_kernel_str(buf, size, d_name.name);

    return 0;
}

// 获取完整路径 (简化版，只往上遍历几层)
statfunc int get_full_path(struct file *file, char *buf, size_t size)
{
    struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
    struct dentry *parent;
    char name[64];
    int offset = size - 1;

    buf[offset] = '\0';

    // 向上遍历目录树 (最多 5 层，避免验证器循环限制)
    #pragma unroll
    for (int i = 0; i < 5; i++) {
        if (!dentry)
            break;

        struct qstr d_name = BPF_CORE_READ(dentry, d_name);
        int name_len = BPF_CORE_READ(dentry, d_name.len);

        if (name_len > sizeof(name) - 1)
            name_len = sizeof(name) - 1;

        bpf_probe_read_kernel_str(name, sizeof(name), d_name.name);

        // 检查是否到达根目录
        parent = BPF_CORE_READ(dentry, d_parent);
        if (dentry == parent)
            break;

        // 前插路径组件
        int copy_len = name_len;
        if (copy_len > offset - 1)
            copy_len = offset - 1;

        offset -= copy_len;
        bpf_probe_read_kernel(&buf[offset], copy_len, name);

        offset--;
        buf[offset] = '/';

        dentry = parent;
    }

    // 移动到缓冲区开头
    if (offset > 0) {
        for (int i = 0; i < size - offset && i < size; i++) {
            buf[i] = buf[offset + i];
        }
    }

    return 0;
}

// ============================================================================
// Kprobe: vfs_read entry
// ============================================================================

SEC("kprobe/vfs_read")
int BPF_KPROBE(trace_vfs_read_entry, struct file *file, char *buf,
               size_t count, loff_t *pos)
{
    u32 tid = bpf_get_current_pid_tgid();

    // 保存参数到 args_map
    struct vfs_args args = {
        .file = file,
        .pos = pos,
        .count = count,
    };
    bpf_map_update_elem(&args_map, &tid, &args, BPF_ANY);

    return 0;
}

// ============================================================================
// Kretprobe: vfs_read return
// ============================================================================

SEC("kretprobe/vfs_read")
int BPF_KRETPROBE(trace_vfs_read_return, ssize_t ret)
{
    u32 tid = bpf_get_current_pid_tgid();

    // 从 args_map 获取保存的参数
    struct vfs_args *args = bpf_map_lookup_elem(&args_map, &tid);
    if (!args)
        return 0;

    // 清理 args_map
    bpf_map_delete_elem(&args_map, &tid);

    // 忽略错误和小读取
    if (ret <= 0)
        return 0;

    // 填充事件
    struct file_event event = {};
    event.timestamp = bpf_ktime_get_ns();
    event.op_type = FILE_OP_READ;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    event.pid = pid_tgid >> 32;
    event.tid = tid;
    event.uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    // 获取文件路径
    get_full_path(args->file, event.path, sizeof(event.path));

    // 填充读取信息
    if (args->pos) {
        bpf_probe_read_kernel(&event.offset, sizeof(event.offset), args->pos);
    }
    event.count = args->count;
    event.ret = ret;

    // 发送事件
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));

    return 0;
}

// ============================================================================
// Kprobe: vfs_write entry
// ============================================================================

SEC("kprobe/vfs_write")
int BPF_KPROBE(trace_vfs_write_entry, struct file *file, const char *buf,
               size_t count, loff_t *pos)
{
    u32 tid = bpf_get_current_pid_tgid();

    struct vfs_args args = {
        .file = file,
        .pos = pos,
        .count = count,
    };
    bpf_map_update_elem(&args_map, &tid, &args, BPF_ANY);

    return 0;
}

// ============================================================================
// Kretprobe: vfs_write return
// ============================================================================

SEC("kretprobe/vfs_write")
int BPF_KRETPROBE(trace_vfs_write_return, ssize_t ret)
{
    u32 tid = bpf_get_current_pid_tgid();

    struct vfs_args *args = bpf_map_lookup_elem(&args_map, &tid);
    if (!args)
        return 0;

    bpf_map_delete_elem(&args_map, &tid);

    if (ret <= 0)
        return 0;

    struct file_event event = {};
    event.timestamp = bpf_ktime_get_ns();
    event.op_type = FILE_OP_WRITE;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    event.pid = pid_tgid >> 32;
    event.tid = tid;
    event.uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    get_full_path(args->file, event.path, sizeof(event.path));

    if (args->pos) {
        bpf_probe_read_kernel(&event.offset, sizeof(event.offset), args->pos);
    }
    event.count = args->count;
    event.ret = ret;

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));

    return 0;
}

// ============================================================================
// License
// ============================================================================

char LICENSE[] SEC("license") = "Dual BSD/GPL";
