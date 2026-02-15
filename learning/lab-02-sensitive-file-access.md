# 实验二：敏感文件访问检测

> 本实验学习如何使用 eBPF 检测对敏感文件（如 /etc/shadow、/etc/passwd）的访问。

---

## 实验目标

完成本实验后，你将能够：

1. 理解文件访问相关的内核 Hook 点
2. 用 Tracee 检测敏感文件访问
3. 自己编写 eBPF 文件监控程序
4. 实现基于路径的过滤逻辑

---

## 实验环境

| 要求 | 说明 |
|------|------|
| 系统 | Linux 虚拟机（推荐 Ubuntu 20.04/22.04） |
| 内核 | 5.4 以上（支持 LSM eBPF 需要 5.7+） |
| 权限 | 需要 root 权限 |
| 软件 | Tracee 已安装、gcc、make |

---

## 第一部分：前置知识

### 1.1 文件访问的内核流程

```
用户程序调用 open("/etc/shadow", O_RDONLY)
                │
                ▼
        系统调用层 (sys_openat)
                │
                ▼
        VFS 层 (vfs_open)
                │
                ▼
        安全检查 (security_file_open)  ← LSM Hook 点
                │
                ▼
        文件系统层 (ext4_file_open)
                │
                ▼
        返回文件描述符
```

### 1.2 可选的 Hook 点

| Hook 点 | 类型 | 特点 |
|---------|------|------|
| `tracepoint/syscalls/sys_enter_openat` | Tracepoint | 稳定，但只有参数，没有权限检查结果 |
| `kprobe/vfs_open` | Kprobe | 可获取文件信息 |
| `lsm/security_file_open` | LSM | 专为安全设计，可获取完整路径 |
| `kprobe/do_sys_openat2` | Kprobe | 系统调用入口 |

**推荐使用 `security_file_open`**：
- 专为安全检测设计
- 可以获取完整的文件路径
- 可以阻止访问（如果需要）

### 1.3 敏感文件列表

常见的敏感文件：

| 文件路径 | 敏感原因 |
|----------|----------|
| `/etc/shadow` | 密码哈希 |
| `/etc/passwd` | 用户信息 |
| `/etc/sudoers` | sudo 配置 |
| `/root/.ssh/` | SSH 密钥 |
| `/etc/ssh/ssh_host_*` | 主机密钥 |
| `/var/run/docker.sock` | Docker Socket |
| `/proc/kcore` | 内核内存 |

---

## 第二部分：Tracee 检测验证

### 2.1 监控所有文件打开

```bash
# 终端 1：启动 Tracee
sudo tracee --events security_file_open

# 终端 2：触发文件访问
cat /etc/passwd
cat /etc/shadow  # 需要 root
```

观察输出：

```
TIME             UID    COMM     PID     EVENT               ARGS
14:32:15.123456  0      cat      12345   security_file_open  pathname: /etc/shadow, flags: O_RDONLY
```

### 2.2 过滤特定文件

```bash
# 只监控 /etc/shadow 访问
sudo tracee --events security_file_open \
    --filter 'event.args.pathname=/etc/shadow'

# 监控多个敏感文件
sudo tracee --events security_file_open \
    --filter 'event.args.pathname=/etc/shadow,/etc/passwd,/etc/sudoers'

# 使用通配符
sudo tracee --events security_file_open \
    --filter 'event.args.pathname=/etc/shadow*'
```

### 2.3 结合容器监控

```bash
# 只监控容器内的敏感文件访问
sudo tracee --events security_file_open \
    --filter 'container=true' \
    --filter 'event.args.pathname=/etc/shadow'
```

### 2.4 使用内置签名

```bash
# Tracee 有一些内置的敏感文件检测签名
sudo tracee --events proc_kcore_read

# 测试
sudo cat /proc/kcore | head -c 100
```

---

## 第三部分：自己实现文件监控

### 3.1 方案选择

我们使用 `kprobe/security_file_open` 作为 Hook 点：

```
security_file_open(struct file *file)
                       │
                       └── file->f_path.dentry->d_name.name  → 文件名
                       └── file->f_path.dentry->d_parent     → 父目录
```

### 3.2 完整 eBPF 代码

创建文件 `file_monitor.bpf.c`：

```c
// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define MAX_PATH_LEN 256
#define MAX_FILENAME_LEN 64

// 文件访问事件
struct file_event {
    u32 pid;
    u32 uid;
    u32 flags;
    char comm[16];
    char filename[MAX_FILENAME_LEN];
    char path[MAX_PATH_LEN];
};

// Perf buffer
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");

// 敏感文件名 Map（用于快速匹配）
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 32);
    __type(key, char[MAX_FILENAME_LEN]);
    __type(value, u8);
} sensitive_files SEC(".maps");

// 辅助函数：获取文件路径
static __always_inline int get_path_str(struct path *path, char *buf, int buflen) {
    struct dentry *dentry;
    struct dentry *parent;
    char *name;
    int len;
    int offset = buflen - 1;

    buf[offset] = '\0';

    BPF_CORE_READ_INTO(&dentry, path, dentry);

    // 简化版：只获取文件名和父目录
    // 完整路径需要递归遍历，这里为了简单只取两层
    #pragma unroll
    for (int i = 0; i < 4; i++) {
        if (!dentry)
            break;

        struct qstr d_name;
        BPF_CORE_READ_INTO(&d_name, dentry, d_name);
        name = (char *)BPF_CORE_READ(&d_name, name);
        len = BPF_CORE_READ(&d_name, len);

        if (len == 0 || len > MAX_FILENAME_LEN)
            break;

        // 检查是否是根目录
        BPF_CORE_READ_INTO(&parent, dentry, d_parent);
        if (parent == dentry)
            break;

        // 添加分隔符
        if (offset > 0 && buf[offset] != '\0') {
            offset--;
            buf[offset] = '/';
        }

        // 添加目录名
        offset -= len;
        if (offset < 0)
            break;

        bpf_probe_read_kernel_str(&buf[offset], len + 1, name);

        dentry = parent;
    }

    // 移动到开头
    if (offset > 0) {
        for (int i = 0; i < buflen - offset; i++) {
            buf[i] = buf[offset + i];
        }
    }

    return 0;
}

// 检查是否为敏感文件
static __always_inline bool is_sensitive(const char *filename) {
    u8 *val = bpf_map_lookup_elem(&sensitive_files, filename);
    return val != NULL;
}

SEC("kprobe/security_file_open")
int BPF_KPROBE(trace_file_open, struct file *file)
{
    struct file_event evt = {};

    // 获取基本信息
    u64 pid_tgid = bpf_get_current_pid_tgid();
    evt.pid = pid_tgid >> 32;
    evt.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));

    // 获取文件标志
    BPF_CORE_READ_INTO(&evt.flags, file, f_flags);

    // 获取文件名
    struct dentry *dentry;
    BPF_CORE_READ_INTO(&dentry, file, f_path.dentry);

    struct qstr d_name;
    BPF_CORE_READ_INTO(&d_name, dentry, d_name);

    const char *name = BPF_CORE_READ(&d_name, name);
    bpf_probe_read_kernel_str(&evt.filename, sizeof(evt.filename), name);

    // 方法一：检查敏感文件列表
    if (is_sensitive(evt.filename)) {
        // 获取更完整的路径
        struct path f_path;
        BPF_CORE_READ_INTO(&f_path, file, f_path);
        get_path_str(&f_path, evt.path, sizeof(evt.path));

        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
                              &evt, sizeof(evt));
        return 0;
    }

    // 方法二：直接匹配文件名（硬编码常见敏感文件）
    // 检查 shadow
    if (evt.filename[0] == 's' && evt.filename[1] == 'h' &&
        evt.filename[2] == 'a' && evt.filename[3] == 'd' &&
        evt.filename[4] == 'o' && evt.filename[5] == 'w' &&
        evt.filename[6] == '\0') {
        struct path f_path;
        BPF_CORE_READ_INTO(&f_path, file, f_path);
        get_path_str(&f_path, evt.path, sizeof(evt.path));

        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
                              &evt, sizeof(evt));
    }

    // 检查 passwd
    if (evt.filename[0] == 'p' && evt.filename[1] == 'a' &&
        evt.filename[2] == 's' && evt.filename[3] == 's' &&
        evt.filename[4] == 'w' && evt.filename[5] == 'd' &&
        evt.filename[6] == '\0') {
        struct path f_path;
        BPF_CORE_READ_INTO(&f_path, file, f_path);
        get_path_str(&f_path, evt.path, sizeof(evt.path));

        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
                              &evt, sizeof(evt));
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
```

### 3.3 用户空间程序

创建文件 `file_monitor.go`：

```go
package main

import (
    "bytes"
    "encoding/binary"
    "fmt"
    "os"
    "os/signal"
    "syscall"

    "github.com/aquasecurity/libbpfgo"
)

const (
    MaxPathLen     = 256
    MaxFilenameLen = 64
)

type FileEvent struct {
    Pid      uint32
    UID      uint32
    Flags    uint32
    Comm     [16]byte
    Filename [MaxFilenameLen]byte
    Path     [MaxPathLen]byte
}

func main() {
    // 加载 BPF 程序
    bpfModule, err := libbpfgo.NewModuleFromFile("file_monitor.bpf.o")
    if err != nil {
        fmt.Fprintf(os.Stderr, "Failed to load BPF module: %v\n", err)
        os.Exit(1)
    }
    defer bpfModule.Close()

    if err := bpfModule.BPFLoadObject(); err != nil {
        fmt.Fprintf(os.Stderr, "Failed to load BPF object: %v\n", err)
        os.Exit(1)
    }

    // 初始化敏感文件列表
    sensitiveMap, err := bpfModule.GetMap("sensitive_files")
    if err != nil {
        fmt.Fprintf(os.Stderr, "Failed to get map: %v\n", err)
        os.Exit(1)
    }

    // 添加敏感文件到 Map
    sensitiveFiles := []string{
        "shadow", "passwd", "sudoers",
        "authorized_keys", "id_rsa", "id_ed25519",
        "docker.sock", "kcore",
    }

    for _, f := range sensitiveFiles {
        key := make([]byte, MaxFilenameLen)
        copy(key, f)
        val := uint8(1)
        if err := sensitiveMap.Update(key, val); err != nil {
            fmt.Printf("Warning: failed to add %s to map: %v\n", f, err)
        }
    }

    // 附加 kprobe
    prog, err := bpfModule.GetProgram("trace_file_open")
    if err != nil {
        fmt.Fprintf(os.Stderr, "Failed to get program: %v\n", err)
        os.Exit(1)
    }

    _, err = prog.AttachKprobe("security_file_open")
    if err != nil {
        fmt.Fprintf(os.Stderr, "Failed to attach kprobe: %v\n", err)
        os.Exit(1)
    }

    // 设置 perf buffer
    eventsChannel := make(chan []byte)
    lostChannel := make(chan uint64)

    pb, err := bpfModule.InitPerfBuf("events", eventsChannel, lostChannel, 1)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Failed to init perf buffer: %v\n", err)
        os.Exit(1)
    }

    pb.Start()

    // 处理信号
    sig := make(chan os.Signal, 1)
    signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

    fmt.Println("Sensitive File Monitor Started...")
    fmt.Println("Monitoring access to: shadow, passwd, sudoers, SSH keys, docker.sock, kcore")
    fmt.Println("Press Ctrl+C to exit")
    fmt.Println()

    // 主循环
    for {
        select {
        case data := <-eventsChannel:
            var evt FileEvent
            if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &evt); err != nil {
                fmt.Fprintf(os.Stderr, "Failed to parse event: %v\n", err)
                continue
            }

            comm := cstring(evt.Comm[:])
            filename := cstring(evt.Filename[:])
            path := cstring(evt.Path[:])

            accessType := "READ"
            if evt.Flags&(syscall.O_WRONLY|syscall.O_RDWR) != 0 {
                accessType = "WRITE"
            }

            fmt.Printf("[ALERT] Sensitive File Access!\n")
            fmt.Printf("  File: %s\n", filename)
            fmt.Printf("  Path: %s\n", path)
            fmt.Printf("  Access: %s\n", accessType)
            fmt.Printf("  Process: %s (PID: %d, UID: %d)\n", comm, evt.Pid, evt.UID)
            fmt.Println()

        case lost := <-lostChannel:
            fmt.Printf("Lost %d events\n", lost)

        case <-sig:
            fmt.Println("\nShutting down...")
            pb.Stop()
            return
        }
    }
}

func cstring(b []byte) string {
    n := bytes.IndexByte(b, 0)
    if n == -1 {
        n = len(b)
    }
    return string(b[:n])
}
```

### 3.4 编译和运行

```bash
# 1. 编译 eBPF 程序
clang -g -O2 -target bpf -D__TARGET_ARCH_x86 \
    -c file_monitor.bpf.c \
    -o file_monitor.bpf.o

# 2. 编译 Go 程序
go build -o file_monitor file_monitor.go

# 3. 运行
sudo ./file_monitor
```

### 3.5 测试

```bash
# 终端 1：运行监控程序
sudo ./file_monitor

# 终端 2：触发敏感文件访问
cat /etc/shadow
cat /etc/passwd
ls /root/.ssh/

# 终端 1 应该输出类似：
# [ALERT] Sensitive File Access!
#   File: shadow
#   Path: etc/shadow
#   Access: READ
#   Process: cat (PID: 12345, UID: 0)
```

---

## 第四部分：进阶优化

### 4.1 完整路径获取

上面的代码简化了路径获取，完整路径需要递归遍历目录：

```c
// 更完整的路径获取（但需要更多循环展开）
static __always_inline int get_full_path(struct file *file, char *buf, int buflen) {
    struct path f_path;
    struct dentry *dentry;
    struct dentry *parent;
    struct dentry *mnt_root;
    struct vfsmount *vfsmnt;

    BPF_CORE_READ_INTO(&f_path, file, f_path);
    dentry = BPF_CORE_READ(&f_path, dentry);
    vfsmnt = BPF_CORE_READ(&f_path, mnt);
    mnt_root = BPF_CORE_READ(vfsmnt, mnt_root);

    int offset = buflen - 1;
    buf[offset] = '\0';

    #pragma unroll
    for (int i = 0; i < 16; i++) {  // 最多 16 层目录
        if (!dentry || dentry == mnt_root)
            break;

        parent = BPF_CORE_READ(dentry, d_parent);
        if (parent == dentry)
            break;

        // 获取当前目录名
        struct qstr d_name = BPF_CORE_READ(dentry, d_name);
        const char *name = d_name.name;
        int len = d_name.len;

        if (len > 0 && len < 64) {
            offset -= len;
            if (offset < 1)
                break;
            bpf_probe_read_kernel(&buf[offset], len, name);
            offset--;
            buf[offset] = '/';
        }

        dentry = parent;
    }

    // 移动字符串到开头
    // ...

    return 0;
}
```

### 4.2 支持通配符匹配

```c
// 简单的前缀匹配
static __always_inline bool match_prefix(const char *str, const char *prefix, int prefix_len) {
    #pragma unroll
    for (int i = 0; i < prefix_len; i++) {
        if (str[i] != prefix[i])
            return false;
    }
    return true;
}

// 示例：匹配 /etc/ 开头的文件
if (match_prefix(path, "/etc/", 5)) {
    // 敏感目录访问
}
```

### 4.3 区分读写操作

```c
// 检查是否为写操作
static __always_inline bool is_write_access(unsigned int flags) {
    return (flags & (O_WRONLY | O_RDWR | O_CREAT | O_TRUNC | O_APPEND)) != 0;
}

// 在 hook 中使用
if (is_write_access(evt.flags)) {
    // 写入敏感文件，更高优先级告警
}
```

### 4.4 结合进程上下文

```c
// 增加父进程检查
struct task_struct *task = (struct task_struct *)bpf_get_current_task();
struct task_struct *parent = BPF_CORE_READ(task, real_parent);
char parent_comm[16];
BPF_CORE_READ_STR_INTO(&parent_comm, parent, comm);

// 如果父进程是 Web 服务，优先级更高
if (parent_comm[0] == 'n' && parent_comm[1] == 'g' &&
    parent_comm[2] == 'i' && parent_comm[3] == 'n' &&
    parent_comm[4] == 'x') {
    // nginx 子进程访问敏感文件
    evt.severity = HIGH;
}
```

---

## 第五部分：检测场景扩展

### 5.1 检测容器内敏感文件访问

```bash
# 在容器中测试
docker run -it ubuntu bash

# 容器内尝试读取
cat /etc/shadow

# 监控程序应该能检测到
# 可以结合 cgroup ID 判断是否来自容器
```

### 5.2 检测 /proc 文件系统滥用

```c
// 检测 /proc/kcore 读取（内核内存泄露）
if (match_prefix(path, "/proc/kcore", 11)) {
    // 高危！
}

// 检测 /proc/kallsyms 读取（获取内核符号）
if (match_prefix(path, "/proc/kallsyms", 14)) {
    // 可能在准备漏洞利用
}
```

### 5.3 检测 Docker Socket 访问

```c
// 检测 docker.sock 访问（容器逃逸前兆）
if (match_suffix(filename, "docker.sock", 11)) {
    // 容器内访问 docker.sock = 可能的逃逸尝试
}
```

---

## 思考题

1. **性能优化**：如果要监控大量文件，如何设计高效的匹配算法？
   - 提示：使用 BPF Map 存储敏感文件列表，哈希匹配

2. **误报处理**：系统正���运行时也会访问 /etc/passwd（如 id 命令），如何减少误报？
   - 提示：白名单、上下文分析、访问频率

3. **绕过检测**：攻击者可能通过哪些方式绕过文件监控？
   - 提示：符号链接、硬链接、挂载覆盖、直接读取块设备

---

## 下一步

完成文件监控实验后，选择继续学习方向：

| 方向 | 链接 | 说明 |
|------|------|------|
| 容器逃逸检测 | [lab-03-container-escape.md](lab-03-container-escape.md) | 学习容器逃逸攻击与检测 |
| 上下文丰富 | [学习路径阶段 4](learning-path-detector-dev.md#阶段-4上下文丰富第-5-6-周) | 添加进程树、容器信息 |

相关文档：
- [进程树与缓存机制](proctree-and-cache.md)
- [容器集成](06-container-integration.md)
- [BPF Maps 深度解析](bpf-maps-deep-dive.md)

---

_最后更新：2026-02-15_
