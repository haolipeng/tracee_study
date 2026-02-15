# 从零搭建 eBPF 安全检测工具

> 本教程带你从零开始，一步步构建一个完整的 eBPF 安全检测工具。

---

## 教程目标

完成本教程后，你将拥有一个功能完整的 mini 检测工具，包括：

- 提权检测（UID 变化监控）
- 敏感文件访问检测
- 进程上下文信息
- JSON 格式输出
- 可配置的检测规则

---

## 目录

1. [项目规划](#1-项目规划)
2. [环境准备](#2-环境准备)
3. [第一步：项目骨架](#3-第一步项目骨架)
4. [第二步：eBPF 程序框架](#4-第二步ebpf-程序框架)
5. [第三步：用户空间程序](#5-第三步用户空间程序)
6. [第四步：添加提权检测](#6-第四步添加提权检测)
7. [第五步：添加文件监控](#7-第五步添加文件监控)
8. [第六步：上下文丰富](#8-第六步上下文丰富)
9. [第七步：规则引擎](#9-第七步规则引擎)
10. [第八步：JSON 输出](#10-第八步json-输出)
11. [完整代码](#11-完整代码)
12. [测试验证](#12-测试验证)

---

## 1. 项目规划

### 1.1 架构设计

```
┌─────────────────────────────────────────────────────────────┐
│                     mini-detector                            │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│   ┌─────────────────────────────────────────────────────┐   │
│   │                    用户空间 (Go)                     │   │
│   │                                                     │   │
│   │  ┌──────────┐  ┌──────────┐  ┌──────────────────┐  │   │
│   │  │ 事件接收  │─▶│ 规则引擎  │─▶│ 输出 (JSON/终端) │  │   │
│   │  └──────────┘  └──────────┘  └──────────────────┘  │   │
│   │       ▲                                             │   │
│   │       │ Ring Buffer                                 │   │
│   └───────┼─────────────────────────────────────────────┘   │
│           │                                                 │
│   ┌───────┼─────────────────────────────────────────────┐   │
│   │       │            内核空间 (eBPF/C)                 │   │
│   │       │                                             │   │
│   │  ┌────┴─────┐  ┌────────────┐  ┌────────────────┐  │   │
│   │  │ 提权检测  │  │ 文件监控   │  │ 上下文收集     │  │   │
│   │  │commit_creds│ │file_open  │  │ task_struct   │  │   │
│   │  └──────────┘  └────────────┘  └────────────────┘  │   │
│   │                                                     │   │
│   └─────────────────────────────────────────────────────┘   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 1.2 技术选型

| 组件 | 选择 | 原因 |
|------|------|------|
| eBPF 库 | libbpfgo | Go 语言友好，Tracee 也在用 |
| 数据传递 | Ring Buffer | 比 Perf Buffer 更高效（内核 5.8+） |
| 用户空间 | Go | 你熟悉，生态好 |
| 输出格式 | JSON | 方便集成 SIEM |

### 1.3 项目结构

```
mini-detector/
├── bpf/
│   ├── detector.bpf.c      # eBPF 程序
│   ├── detector.h          # 共享的数据结构
│   └── vmlinux.h           # 内核类型定义
├── pkg/
│   ├── detector/
│   │   ├── detector.go     # 主检测器
│   │   └── events.go       # 事件定义
│   ├── rules/
│   │   └── engine.go       # 规则引擎
│   └── output/
│       └── json.go         # JSON 输出
├── cmd/
│   └── mini-detector/
│       └── main.go         # 入口
├── Makefile
├── go.mod
└── README.md
```

---

## 2. 环境准备

### 2.1 系统要求

```bash
# 检查内核版本（需要 5.8+，推荐 5.15+）
uname -r

# 检查 BTF 支持
ls /sys/kernel/btf/vmlinux

# 检查 BPF 文件系统
mount | grep bpf
```

### 2.2 安装依赖

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install -y \
    clang \
    llvm \
    libbpf-dev \
    linux-headers-$(uname -r) \
    linux-tools-$(uname -r) \
    golang-go

# 安装 bpftool
sudo apt install -y linux-tools-common linux-tools-generic

# 验证
clang --version
bpftool version
go version
```

### 2.3 生成 vmlinux.h

```bash
# 从 BTF 生成内核类型定义
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
```

---

## 3. 第一步：项目骨架

### 3.1 创建目录结构

```bash
mkdir -p mini-detector/{bpf,pkg/{detector,rules,output},cmd/mini-detector}
cd mini-detector

# 初始化 Go 模块
go mod init mini-detector
```

### 3.2 创建 Makefile

```makefile
# Makefile

CLANG ?= clang
GO ?= go
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

BPF_SRC := bpf/detector.bpf.c
BPF_OBJ := bpf/detector.bpf.o
VMLINUX := bpf/vmlinux.h

.PHONY: all clean vmlinux bpf build run

all: vmlinux bpf build

# 生成 vmlinux.h
vmlinux: $(VMLINUX)

$(VMLINUX):
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

# 编译 eBPF 程序
bpf: $(BPF_OBJ)

$(BPF_OBJ): $(BPF_SRC) $(VMLINUX)
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) \
		-I./bpf \
		-c $< -o $@

# 编译 Go 程序
build:
	CGO_ENABLED=1 $(GO) build -o mini-detector ./cmd/mini-detector

# 运行
run: all
	sudo ./mini-detector

# 清理
clean:
	rm -f $(BPF_OBJ) mini-detector
```

---

## 4. 第二步：eBPF 程序框架

### 4.1 共享头文件

创建 `bpf/detector.h`：

```c
#ifndef __DETECTOR_H__
#define __DETECTOR_H__

// 事件类型
enum event_type {
    EVENT_PRIV_ESCALATION = 1,  // 提权事件
    EVENT_FILE_ACCESS = 2,       // 文件访问事件
};

// 基础事件结构（所有事件共有）
struct event_base {
    __u32 type;          // 事件类型
    __u32 pid;           // 进程 ID
    __u32 tid;           // 线程 ID
    __u32 ppid;          // 父进程 ID
    __u32 uid;           // 用户 ID
    __u64 timestamp;     // 时间戳
    char comm[16];       // 进程名
    char parent_comm[16]; // 父进程名
};

// 提权事件
struct priv_escalation_event {
    struct event_base base;
    __u32 old_uid;
    __u32 new_uid;
    __u32 old_euid;
    __u32 new_euid;
};

// 文件访问事件
struct file_access_event {
    struct event_base base;
    __u32 flags;
    char filename[64];
    char path[256];
};

// 联合体，便于统一处理
struct event {
    union {
        struct event_base base;
        struct priv_escalation_event priv;
        struct file_access_event file;
    };
};

#define MAX_EVENT_SIZE sizeof(struct event)

#endif /* __DETECTOR_H__ */
```

### 4.2 eBPF 程序主体

创建 `bpf/detector.bpf.c`：

```c
// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "detector.h"

// Ring Buffer 用于向用户空间发送事件
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // 256KB
} events SEC(".maps");

// 敏感文件名 Map
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, char[64]);
    __type(value, __u8);
} sensitive_files SEC(".maps");

// 辅助函数：填充基础事件信息
static __always_inline void fill_event_base(struct event_base *base, __u32 type) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent;

    base->type = type;
    base->timestamp = bpf_ktime_get_ns();

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    base->pid = pid_tgid >> 32;
    base->tid = pid_tgid & 0xFFFFFFFF;
    base->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    bpf_get_current_comm(&base->comm, sizeof(base->comm));

    // 获取父进程信息
    BPF_CORE_READ_INTO(&parent, task, real_parent);
    if (parent) {
        BPF_CORE_READ_INTO(&base->ppid, parent, tgid);
        BPF_CORE_READ_STR_INTO(&base->parent_comm, parent, comm);
    }
}

// ============ 提权检测 ============

SEC("kprobe/commit_creds")
int BPF_KPROBE(trace_commit_creds, struct cred *new_cred)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    const struct cred *old_cred;

    // 获取旧凭证
    BPF_CORE_READ_INTO(&old_cred, task, real_cred);
    if (!old_cred || !new_cred)
        return 0;

    // 读取 UID/EUID
    __u32 old_uid, new_uid, old_euid, new_euid;

    old_uid = BPF_CORE_READ(old_cred, uid.val);
    new_uid = BPF_CORE_READ(new_cred, uid.val);
    old_euid = BPF_CORE_READ(old_cred, euid.val);
    new_euid = BPF_CORE_READ(new_cred, euid.val);

    // 检测提权：从非 root 变成 root
    if ((old_euid != 0 && new_euid == 0) ||
        (old_uid != 0 && new_uid == 0)) {

        // 分配 Ring Buffer 空间
        struct priv_escalation_event *e;
        e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
        if (!e)
            return 0;

        // 填充事件
        fill_event_base(&e->base, EVENT_PRIV_ESCALATION);
        e->old_uid = old_uid;
        e->new_uid = new_uid;
        e->old_euid = old_euid;
        e->new_euid = new_euid;

        // 提交事件
        bpf_ringbuf_submit(e, 0);
    }

    return 0;
}

// ============ 文件访问检测 ============

SEC("kprobe/security_file_open")
int BPF_KPROBE(trace_file_open, struct file *file)
{
    if (!file)
        return 0;

    // 获取文件名
    struct dentry *dentry;
    BPF_CORE_READ_INTO(&dentry, file, f_path.dentry);
    if (!dentry)
        return 0;

    char filename[64] = {};
    struct qstr d_name;
    BPF_CORE_READ_INTO(&d_name, dentry, d_name);
    bpf_probe_read_kernel_str(&filename, sizeof(filename), d_name.name);

    // 检查是否为敏感文件
    __u8 *is_sensitive = bpf_map_lookup_elem(&sensitive_files, &filename);

    // 也检查硬编码的敏感文件
    bool is_shadow = (filename[0] == 's' && filename[1] == 'h' &&
                      filename[2] == 'a' && filename[3] == 'd' &&
                      filename[4] == 'o' && filename[5] == 'w' &&
                      filename[6] == '\0');

    bool is_passwd = (filename[0] == 'p' && filename[1] == 'a' &&
                      filename[2] == 's' && filename[3] == 's' &&
                      filename[4] == 'w' && filename[5] == 'd' &&
                      filename[6] == '\0');

    if (is_sensitive || is_shadow || is_passwd) {
        // 分配 Ring Buffer 空间
        struct file_access_event *e;
        e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
        if (!e)
            return 0;

        // 填充事件
        fill_event_base(&e->base, EVENT_FILE_ACCESS);
        BPF_CORE_READ_INTO(&e->flags, file, f_flags);

        // 复制文件名
        __builtin_memcpy(e->filename, filename, sizeof(e->filename));

        // 简化：只存文件名，完整路径在用户空间处理
        e->path[0] = '\0';

        bpf_ringbuf_submit(e, 0);
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
```

---

## 5. 第三步：用户空间程序

### 5.1 事件定义

创建 `pkg/detector/events.go`：

```go
package detector

// 事件类型
const (
    EventPrivEscalation = 1
    EventFileAccess     = 2
)

// 基础事件
type EventBase struct {
    Type       uint32
    PID        uint32
    TID        uint32
    PPID       uint32
    UID        uint32
    Timestamp  uint64
    Comm       [16]byte
    ParentComm [16]byte
}

// 提权事件
type PrivEscalationEvent struct {
    Base    EventBase
    OldUID  uint32
    NewUID  uint32
    OldEUID uint32
    NewEUID uint32
}

// 文件访问事件
type FileAccessEvent struct {
    Base     EventBase
    Flags    uint32
    Filename [64]byte
    Path     [256]byte
}

// 通用事件（用于输出）
type Event struct {
    Type       string            `json:"type"`
    Timestamp  uint64            `json:"timestamp"`
    PID        uint32            `json:"pid"`
    PPID       uint32            `json:"ppid"`
    UID        uint32            `json:"uid"`
    Comm       string            `json:"comm"`
    ParentComm string            `json:"parent_comm"`
    Details    map[string]interface{} `json:"details"`
    Severity   string            `json:"severity"`
}
```

### 5.2 主检测器

创建 `pkg/detector/detector.go`：

```go
package detector

import (
    "bytes"
    "encoding/binary"
    "fmt"
    "os"
    "os/signal"
    "syscall"

    "github.com/aquasecurity/libbpfgo"
)

type Detector struct {
    module     *libbpfgo.Module
    ringbuf    *libbpfgo.RingBuffer
    eventsChan chan Event
    stopChan   chan struct{}
}

func New(bpfObjPath string) (*Detector, error) {
    // 加载 BPF 程序
    module, err := libbpfgo.NewModuleFromFile(bpfObjPath)
    if err != nil {
        return nil, fmt.Errorf("failed to load BPF module: %w", err)
    }

    if err := module.BPFLoadObject(); err != nil {
        module.Close()
        return nil, fmt.Errorf("failed to load BPF object: %w", err)
    }

    return &Detector{
        module:     module,
        eventsChan: make(chan Event, 1000),
        stopChan:   make(chan struct{}),
    }, nil
}

func (d *Detector) Start() error {
    // 附加提权检测探针
    progPriv, err := d.module.GetProgram("trace_commit_creds")
    if err != nil {
        return fmt.Errorf("failed to get priv program: %w", err)
    }
    if _, err := progPriv.AttachKprobe("commit_creds"); err != nil {
        return fmt.Errorf("failed to attach priv kprobe: %w", err)
    }

    // 附加文件监控探针
    progFile, err := d.module.GetProgram("trace_file_open")
    if err != nil {
        return fmt.Errorf("failed to get file program: %w", err)
    }
    if _, err := progFile.AttachKprobe("security_file_open"); err != nil {
        return fmt.Errorf("failed to attach file kprobe: %w", err)
    }

    // 初始化敏感文件列表
    if err := d.initSensitiveFiles(); err != nil {
        fmt.Printf("Warning: failed to init sensitive files: %v\n", err)
    }

    // 设置 Ring Buffer
    d.ringbuf, err = d.module.InitRingBuf("events", d.handleEvent)
    if err != nil {
        return fmt.Errorf("failed to init ring buffer: %w", err)
    }

    d.ringbuf.Poll(300) // 300ms 轮询

    return nil
}

func (d *Detector) initSensitiveFiles() error {
    sensitiveMap, err := d.module.GetMap("sensitive_files")
    if err != nil {
        return err
    }

    files := []string{
        "shadow", "passwd", "sudoers",
        "authorized_keys", "id_rsa", "id_ed25519",
        "docker.sock", "kcore",
    }

    for _, f := range files {
        key := make([]byte, 64)
        copy(key, f)
        val := uint8(1)
        if err := sensitiveMap.Update(key, val); err != nil {
            fmt.Printf("Warning: failed to add %s: %v\n", f, err)
        }
    }

    return nil
}

func (d *Detector) handleEvent(data []byte) {
    if len(data) < 4 {
        return
    }

    // 读取事件类型
    eventType := binary.LittleEndian.Uint32(data[0:4])

    var event Event

    switch eventType {
    case EventPrivEscalation:
        var e PrivEscalationEvent
        if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &e); err != nil {
            return
        }
        event = d.parsePrivEvent(&e)

    case EventFileAccess:
        var e FileAccessEvent
        if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &e); err != nil {
            return
        }
        event = d.parseFileEvent(&e)

    default:
        return
    }

    select {
    case d.eventsChan <- event:
    default:
        // 通道满了，丢弃事件
    }
}

func (d *Detector) parsePrivEvent(e *PrivEscalationEvent) Event {
    severity := "HIGH"
    comm := cstring(e.Base.Comm[:])

    // 白名单检查
    if isWhitelisted(comm) {
        severity = "INFO"
    }

    return Event{
        Type:       "PRIVILEGE_ESCALATION",
        Timestamp:  e.Base.Timestamp,
        PID:        e.Base.PID,
        PPID:       e.Base.PPID,
        UID:        e.Base.UID,
        Comm:       comm,
        ParentComm: cstring(e.Base.ParentComm[:]),
        Severity:   severity,
        Details: map[string]interface{}{
            "old_uid":  e.OldUID,
            "new_uid":  e.NewUID,
            "old_euid": e.OldEUID,
            "new_euid": e.NewEUID,
        },
    }
}

func (d *Detector) parseFileEvent(e *FileAccessEvent) Event {
    accessType := "READ"
    if e.Flags&(syscall.O_WRONLY|syscall.O_RDWR) != 0 {
        accessType = "WRITE"
    }

    return Event{
        Type:       "SENSITIVE_FILE_ACCESS",
        Timestamp:  e.Base.Timestamp,
        PID:        e.Base.PID,
        PPID:       e.Base.PPID,
        UID:        e.Base.UID,
        Comm:       cstring(e.Base.Comm[:]),
        ParentComm: cstring(e.Base.ParentComm[:]),
        Severity:   "MEDIUM",
        Details: map[string]interface{}{
            "filename":    cstring(e.Filename[:]),
            "access_type": accessType,
        },
    }
}

func (d *Detector) Events() <-chan Event {
    return d.eventsChan
}

func (d *Detector) Stop() {
    close(d.stopChan)
    if d.ringbuf != nil {
        d.ringbuf.Stop()
    }
    if d.module != nil {
        d.module.Close()
    }
}

func cstring(b []byte) string {
    n := bytes.IndexByte(b, 0)
    if n == -1 {
        n = len(b)
    }
    return string(b[:n])
}

func isWhitelisted(comm string) bool {
    whitelist := []string{"sudo", "su", "login", "sshd", "cron", "polkitd"}
    for _, w := range whitelist {
        if comm == w {
            return true
        }
    }
    return false
}
```

### 5.3 主程序

创建 `cmd/mini-detector/main.go`：

```go
package main

import (
    "encoding/json"
    "flag"
    "fmt"
    "os"
    "os/signal"
    "syscall"
    "time"

    "mini-detector/pkg/detector"
)

func main() {
    bpfObj := flag.String("bpf", "bpf/detector.bpf.o", "Path to BPF object file")
    jsonOutput := flag.Bool("json", false, "Output in JSON format")
    flag.Parse()

    fmt.Println("╔════════════════════════════════════════════════════╗")
    fmt.Println("║           Mini eBPF Security Detector              ║")
    fmt.Println("╚════════════════════════════════════════════════════╝")
    fmt.Println()

    // 创建检测器
    det, err := detector.New(*bpfObj)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Failed to create detector: %v\n", err)
        os.Exit(1)
    }
    defer det.Stop()

    // 启动检测
    if err := det.Start(); err != nil {
        fmt.Fprintf(os.Stderr, "Failed to start detector: %v\n", err)
        os.Exit(1)
    }

    fmt.Println("[*] Detector started successfully")
    fmt.Println("[*] Monitoring for:")
    fmt.Println("    - Privilege escalation (UID changes to root)")
    fmt.Println("    - Sensitive file access (shadow, passwd, etc.)")
    fmt.Println()
    fmt.Println("Press Ctrl+C to exit")
    fmt.Println()

    // 处理信号
    sig := make(chan os.Signal, 1)
    signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

    // 主循环
    for {
        select {
        case event := <-det.Events():
            if *jsonOutput {
                printJSON(event)
            } else {
                printPretty(event)
            }

        case <-sig:
            fmt.Println("\n[*] Shutting down...")
            return
        }
    }
}

func printJSON(event detector.Event) {
    data, err := json.Marshal(event)
    if err != nil {
        return
    }
    fmt.Println(string(data))
}

func printPretty(event detector.Event) {
    ts := time.Unix(0, int64(event.Timestamp)).Format("15:04:05.000")

    var severityColor string
    switch event.Severity {
    case "HIGH":
        severityColor = "\033[31m" // 红色
    case "MEDIUM":
        severityColor = "\033[33m" // 黄色
    default:
        severityColor = "\033[32m" // 绿色
    }
    resetColor := "\033[0m"

    fmt.Printf("%s[%s]%s %s | %s\n",
        severityColor, event.Severity, resetColor,
        ts, event.Type)
    fmt.Printf("  Process: %s (PID: %d, PPID: %d, UID: %d)\n",
        event.Comm, event.PID, event.PPID, event.UID)
    fmt.Printf("  Parent:  %s\n", event.ParentComm)

    for k, v := range event.Details {
        fmt.Printf("  %s: %v\n", k, v)
    }
    fmt.Println()
}
```

---

## 6. 编译和运行

### 6.1 安装 Go 依赖

```bash
go get github.com/aquasecurity/libbpfgo
```

### 6.2 编译

```bash
make all
```

### 6.3 运行

```bash
# 普通模式
sudo ./mini-detector

# JSON 输出模式
sudo ./mini-detector --json
```

### 6.4 测试

```bash
# 终端 1：运行检测器
sudo ./mini-detector

# 终端 2：触发提权
sudo chmod u+s /usr/bin/find
su - testuser
find /etc/passwd -exec whoami \;

# 终端 2：触发敏感文件访问
cat /etc/shadow
cat /etc/passwd
```

预期输出：

```
[HIGH] 14:32:15.123 | PRIVILEGE_ESCALATION
  Process: find (PID: 12345, PPID: 12340, UID: 1000)
  Parent:  bash
  old_euid: 1000
  new_euid: 0

[MEDIUM] 14:32:20.456 | SENSITIVE_FILE_ACCESS
  Process: cat (PID: 12346, PPID: 12340, UID: 0)
  Parent:  bash
  filename: shadow
  access_type: READ
```

---

## 7. 扩展思路

### 7.1 添加更多检测

```c
// 内核模块加载检测
SEC("kprobe/do_init_module")
int trace_module_load(...) { ... }

// 网络连接检测
SEC("kprobe/tcp_connect")
int trace_tcp_connect(...) { ... }

// 进程执行检测
SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(...) { ... }
```

### 7.2 添加配置文件

```yaml
# config.yaml
rules:
  - name: privilege_escalation
    enabled: true
    severity: high
    whitelist:
      - sudo
      - su
      - cron

  - name: sensitive_file_access
    enabled: true
    severity: medium
    files:
      - /etc/shadow
      - /etc/passwd
```

### 7.3 添加容器检测

```go
// 通过 cgroup ID 判断是否在容器中
func isContainer(cgroupID uint64) bool {
    // 读取 /proc/pid/cgroup 判断
}
```

---

## 8. 完整项目获取

完整的项目代码已放在 `mini-detector/` 目录下，你可以直接使用：

```bash
cd mini-detector
make all
sudo ./mini-detector
```

---

## 9. 下一步

恭喜完成检测工具的搭建！继续学习：

### 扩展检测能力

- [容器逃逸攻防实验](lab-03-container-escape.md) - 为你的工具添加容器逃逸检测

### 深入学习

- [检测设计方法论](detection-design-methodology.md) - 如何从攻击手法推导检测规则
- [Tracee 架构概览](01-architecture-overview.md) - 学习工业级检测工具的设计
- [BPF Maps 深度解析](bpf-maps-deep-dive.md) - 优化你的检测工具

---

_最后更新：2026-02-15_
