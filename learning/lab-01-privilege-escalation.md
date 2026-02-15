# 实验一：本地提权攻击与检测

> 本实验采用「攻击复现 → Tracee 检测 → 自己实现」的三步学习法。

---

## 实验目标

完成本实验后，你将能够：

1. 复现 SUID 提权攻击
2. 用 Tracee 检测到��权行为
3. 理解 commit_creds 检测原理
4. 自己编写 eBPF 提权检测程序

---

## 实验环境

| 要求 | 说明 |
|------|------|
| 系统 | Linux 虚拟机（推荐 Ubuntu 20.04/22.04） |
| 内核 | 5.4 以上 |
| 权限 | 需要 root 权限（用于设置 SUID、运行 Tracee） |
| 软件 | Tracee 已安装、gcc、make |

### 环境检查

```bash
# 检查内核版本
uname -r

# 检查 Tracee 是否可用
sudo tracee --version

# 创建测试用户（如果没有）
sudo useradd -m testuser
sudo passwd testuser  # 设置密码
```

---

## 第一部分：前置知识（5分钟速览）

### 1.1 什么是 UID 和 EUID

```
每个进程都有多个 UID：

┌─────────────────────────────────────────┐
│  UID (Real UID)                         │
│  → 谁启动了这个进程                       │
│  → 例：普通用户 testuser 的 UID = 1000   │
├─────────────────────────────────────────┤
│  EUID (Effective UID)  ← 最重要！        │
│  → 决定进程的实际权限                     │
│  → EUID = 0 意味着 root 权限             │
├─────────────────────────────────────────┤
│  SUID (Saved UID)                       │
│  → 用于临时降权后恢复                     │
└─────────────────────────────────────────┘
```

### 1.2 什么是 SUID

```
正常可执行文件：
-rwxr-xr-x  →  执行时，EUID = 启动用户的 UID

SUID 可执行文件：
-rwsr-xr-x  →  执行时，EUID = 文件所有者的 UID
   ↑
   s 表示 SUID 位
```

**举例**：

```bash
# passwd 是 SUID 程序，所有者是 root
$ ls -l /usr/bin/passwd
-rwsr-xr-x 1 root root ... /usr/bin/passwd

# 普通用户执行 passwd 时
# UID = 1000 (testuser)
# EUID = 0 (root)  ← 可以修改 /etc/shadow
```

### 1.3 commit_creds 函数

**commit_creds 是内核中让凭证生效的函数。**

无论通过什么方式获得新权限（sudo、SUID、漏洞利用），最终都要调用它：

```c
// 内核代码简化版
int commit_creds(struct cred *new) {
    struct task_struct *task = current;
    const struct cred *old = task->real_cred;

    // 替换凭证
    task->real_cred = new;
    task->cred = new;

    return 0;
}
```

**这就是为什么 hook commit_creds 能检测所有提权！**

---

## 第二部分：SUID 提权复现

### 2.1 实验场景

模拟攻击者获得了普通用户 shell，利用配置错误的 SUID 程序提权。

### 2.2 实验步骤

**步骤 1：创建 SUID 漏洞环境**

```bash
# 以 root 身份执行
# 给 find 命令设置 SUID 位（这是一个常见的配置错误）
sudo chmod u+s /usr/bin/find

# 验证 SUID 位已设置
ls -l /usr/bin/find
# 输出应该是：-rwsr-xr-x 1 root root ... /usr/bin/find
#                ↑ 注意这个 s
```

**步骤 2：切换到普通用户**

```bash
# 切换到测试用户
su - testuser

# 确认当前身份
id
# 输出：uid=1000(testuser) gid=1000(testuser) groups=1000(testuser)
```

**步骤 3：利用 find 执行 root 命令**

```bash
# 利用 find 的 -exec 参数执行命令
# find 以 root 权限运行，所以 -exec 的命令也是 root 权限

# 查看当前用户
whoami
# 输出：testuser

# 通过 find 执行 whoami
find /etc/passwd -exec whoami \;
# 输出：root  ← 注意这里变成了 root！

# 读取只有 root 能读的文件
find /etc/passwd -exec cat /etc/shadow \;
# 成功读取！

# 获取 root shell
find /etc/passwd -exec /bin/bash -p \;
# -p 参数保留 EUID
# 现在你有了 root shell
```

**步骤 4：验证提权成功**

```bash
# 在新 shell 中
id
# 输出：uid=1000(testuser) gid=1000(testuser) euid=0(root) groups=1000(testuser)
#                                              ↑ EUID 变成了 0
```

### 2.3 清理环境

```bash
# 实验完成后，移除 SUID 位
sudo chmod u-s /usr/bin/find

# 验证
ls -l /usr/bin/find
# 应该是：-rwxr-xr-x（没有 s 了）
```

---

## 第三部分：Tracee 检测验证

### 3.1 启动 Tracee 监控

打开一个新终端（保持 root 权限）：

```bash
# 方式一：监控所有 setuid 相关事件
sudo tracee --events setuid,setgid,setreuid,setregid,commit_creds

# 方式二：使用签名检测
sudo tracee --events priv_escalation_privilege_uid,dropped_executable

# 方式三：最简单，监控 commit_creds
sudo tracee --events commit_creds
```

### 3.2 执行攻击并观察

在另一个终端执行 SUID 提权攻击（参考第二部分）。

观察 Tracee 输出：

```
TIME             UID    COMM         PID     TID     RET    EVENT           ARGS
14:32:15.123456  1000   find         12345   12345   0      commit_creds    new_uid: 0, new_euid: 0, old_uid: 1000, old_euid: 1000

                                                            ↑
                                                     检测到 UID 从 1000 变成 0
```

### 3.3 分析检测结果

```
关键信息：
├── COMM = find         → 是 find 命令触发的
├── UID = 1000          → 原始用户是普通用户
├── old_euid = 1000     → 之前的有效 UID
├── new_euid = 0        → 变成了 root
└── 事件 = commit_creds → 权限变化生效
```

**思考**：为什么 Tracee 能检测到这个提权？

因为 Tracee 在 `commit_creds` 函数上设置了 hook，无论通过什么方式提权，只要权限变化就会被捕获。

---

## 第四部分：自己实现提权检测

### 4.1 完整代码

创建文件 `priv_escalation_detector.bpf.c`：

```c
// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// 定义事件结构
struct event {
    u32 pid;
    u32 tid;
    u32 ppid;
    u32 old_uid;
    u32 old_euid;
    u32 new_uid;
    u32 new_euid;
    char comm[16];
    char parent_comm[16];
};

// Perf buffer 用于向用户空间发送事件
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");

// 辅助函数：读取 cred 结构中的 UID
static __always_inline u32 read_uid(const struct cred *cred) {
    kuid_t uid;
    BPF_CORE_READ_INTO(&uid, cred, uid);
    return uid.val;
}

static __always_inline u32 read_euid(const struct cred *cred) {
    kuid_t euid;
    BPF_CORE_READ_INTO(&euid, cred, euid);
    return euid.val;
}

// Hook commit_creds 函数
SEC("kprobe/commit_creds")
int BPF_KPROBE(trace_commit_creds, struct cred *new_cred)
{
    struct event evt = {};

    // 获取当前进程信息
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task)
        return 0;

    // 获取 PID 和 TID
    u64 pid_tgid = bpf_get_current_pid_tgid();
    evt.pid = pid_tgid >> 32;
    evt.tid = pid_tgid & 0xFFFFFFFF;

    // 获取进程名
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));

    // 获取父进程信息
    struct task_struct *parent;
    BPF_CORE_READ_INTO(&parent, task, real_parent);
    if (parent) {
        BPF_CORE_READ_INTO(&evt.ppid, parent, tgid);
        BPF_CORE_READ_STR_INTO(&evt.parent_comm, parent, comm);
    }

    // 获取旧凭证（当前生效的凭证）
    const struct cred *old_cred;
    BPF_CORE_READ_INTO(&old_cred, task, real_cred);
    if (!old_cred)
        return 0;

    // 读取旧凭证的 UID/EUID
    evt.old_uid = read_uid(old_cred);
    evt.old_euid = read_euid(old_cred);

    // 读取新凭证的 UID/EUID
    evt.new_uid = read_uid(new_cred);
    evt.new_euid = read_euid(new_cred);

    // 检测提权：从非 root 变成 root
    if (evt.old_euid != 0 && evt.new_euid == 0) {
        // 检测到提权！发送事件
        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
                              &evt, sizeof(evt));
    }

    // 也可以检测 UID 变化
    if (evt.old_uid != 0 && evt.new_uid == 0) {
        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
                              &evt, sizeof(evt));
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
```

### 4.2 用户空间程序

创建文件 `main.go`：

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

// 与 eBPF 程序中的结构体对应
type Event struct {
    Pid        uint32
    Tid        uint32
    Ppid       uint32
    OldUID     uint32
    OldEUID    uint32
    NewUID     uint32
    NewEUID    uint32
    Comm       [16]byte
    ParentComm [16]byte
}

func main() {
    // 加载 BPF 程序
    bpfModule, err := libbpfgo.NewModuleFromFile("priv_escalation_detector.bpf.o")
    if err != nil {
        fmt.Fprintf(os.Stderr, "Failed to load BPF module: %v\n", err)
        os.Exit(1)
    }
    defer bpfModule.Close()

    // 加载到内核
    if err := bpfModule.BPFLoadObject(); err != nil {
        fmt.Fprintf(os.Stderr, "Failed to load BPF object: %v\n", err)
        os.Exit(1)
    }

    // 附加 kprobe
    prog, err := bpfModule.GetProgram("trace_commit_creds")
    if err != nil {
        fmt.Fprintf(os.Stderr, "Failed to get program: %v\n", err)
        os.Exit(1)
    }

    _, err = prog.AttachKprobe("commit_creds")
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

    fmt.Println("Privilege Escalation Detector Started...")
    fmt.Println("Monitoring for UID changes to root (EUID -> 0)")
    fmt.Println("Press Ctrl+C to exit")
    fmt.Println()

    // 主循环
    for {
        select {
        case data := <-eventsChannel:
            var evt Event
            if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &evt); err != nil {
                fmt.Fprintf(os.Stderr, "Failed to parse event: %v\n", err)
                continue
            }

            comm := string(bytes.TrimRight(evt.Comm[:], "\x00"))
            parentComm := string(bytes.TrimRight(evt.ParentComm[:], "\x00"))

            // 判断是否为可疑提权
            severity := "INFO"
            if !isWhitelisted(comm) {
                severity = "WARNING"
            }

            fmt.Printf("[%s] Privilege Escalation Detected!\n", severity)
            fmt.Printf("  PID: %d, PPID: %d\n", evt.Pid, evt.Ppid)
            fmt.Printf("  Process: %s (parent: %s)\n", comm, parentComm)
            fmt.Printf("  UID:  %d -> %d\n", evt.OldUID, evt.NewUID)
            fmt.Printf("  EUID: %d -> %d\n", evt.OldEUID, evt.NewEUID)
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

// 白名单进程（正常的提权程序）
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

### 4.3 编译和运行

```bash
# 1. 生成 vmlinux.h（如果没有）
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

# 2. 编译 eBPF 程序
clang -g -O2 -target bpf -D__TARGET_ARCH_x86 \
    -c priv_escalation_detector.bpf.c \
    -o priv_escalation_detector.bpf.o

# 3. 编译 Go 程序
go mod init priv_detector
go get github.com/aquasecurity/libbpfgo
go build -o priv_detector main.go

# 4. 运行（需要 root 权限）
sudo ./priv_detector
```

### 4.4 测试检测效果

```bash
# 终端 1：运行检测器
sudo ./priv_detector

# 终端 2：执行提权攻击
sudo chmod u+s /usr/bin/find
su - testuser
find /etc/passwd -exec whoami \;

# 终端 1 应该输出：
# [WARNING] Privilege Escalation Detected!
#   PID: 12345, PPID: 12340
#   Process: find (parent: bash)
#   UID:  1000 -> 1000
#   EUID: 1000 -> 0
```

---

## 第五部分：深入理解

### 5.1 为什么选择 hook commit_creds

```
对比不同 Hook 点：

┌────────────────────┬─────────────────┬─────────────────┐
│ Hook 点            │ 能检测的场景     │ 缺点            │
├────────────────────┼─────────────────┼─────────────────┤
│ sys_enter_setuid   │ setuid 调用     │ 只看到请求      │
│                    │                 │ 不知道是否成功   │
├────────────────────┼─────────────────┼─────────────────┤
│ sys_exit_setuid    │ setuid 结果     │ 需要多个 hook   │
│                    │                 │ 无法覆盖漏洞利用 │
├────────────────────┼─────────────────┼─────────────────┤
│ commit_creds       │ 所有权限变化     │ 内部函数        │
│ （我们的选择）      │ 包括漏洞利用     │ （但很稳定）     │
└────────────────────┴─────────────────┴─────────────────┘
```

### 5.2 如何区分正常提权和恶意提权

```
正常提权特征：
├── 进程名：sudo, su, login, sshd, cron
├── 父进程：shell 或 init
└── 场景：用户主动执行

可疑提权特征：
├── 进程名：find, vim, python, bash 等普通程序
├── 父进程：Web 服务（nginx, apache）、脚本
└── 场景：意外的权限变化
```

### 5.3 扩展思考

1. **如何检测内核漏洞提权？**
   - 同样的方法！因为内核漏洞最终也要调用 commit_creds
   - 可以增加调用栈分析，正常路径 vs 异常路径

2. **如何减少误报？**
   - 维护白名单
   - 检查父进程链
   - 结合其他事件（如 execve）

3. **性能考虑？**
   - commit_creds 调用频率不高
   - 早期过滤（在 eBPF 中过滤）

---

## 思考题

完成实验后，思考以下问题：

1. 除了 find，还有哪些常见程序可能被滥用于 SUID 提权？
   - 提示：查看 GTFOBins 网站

2. 如何检测 capabilities 的提升（如获得 CAP_SYS_ADMIN）？
   - 提示：cred 结构中有 cap_effective 字段

3. 如果攻击者利用内核漏洞直接修改 cred 结构，我们的检测能发现吗？
   - 提示：取决于漏洞利用方式，大多数会调用 commit_creds

---

## 下一步

恭喜完成提权检测实验！选择继续学习方向：

| 方向 | 链接 | 说明 |
|------|------|------|
| 文件监控 | [lab-02-sensitive-file-access.md](lab-02-sensitive-file-access.md) | 敏感文件访问检测（推荐） |
| 容器逃逸 | [lab-03-container-escape.md](lab-03-container-escape.md) | 容器逃逸攻击与检测 |

👉 **推荐按顺序学习 lab-01 → lab-02 → lab-03**

---

## 参考资料

- [GTFOBins](https://gtfobins.github.io/) - Unix 二进制利用技术
- [Linux 内核 cred.c](https://elixir.bootlin.com/linux/latest/source/kernel/cred.c)
- [libbpfgo 文档](https://github.com/aquasecurity/libbpfgo)

---

_最后更新：2026-02-15_
