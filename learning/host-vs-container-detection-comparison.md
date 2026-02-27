# 高危命令检测：主机 vs 容器环境对比

> 文档版本：1.0
> 创建日期：2026-02-27
> 关联签名：TRC-CUSTOM-001 (Dangerous Command Execution)

---

## 目录

1. [概述](#1-概述)
2. [底层检测机制对比](#2-底层检测机制对比)
3. [事件来源区分机制](#3-事件来源区分机制)
4. [行为基线差异](#4-行为基线差异)
5. [签名规则的 Origin 过滤](#5-签名规则的-origin-过滤)
6. [案例分析：DangerousCommandExecution 签名](#6-案例分析dangerouscommandexecution-签名)
7. [威胁模型对比表](#7-威胁模型对比表)
8. [关联文档](#8-关联文档)

---

## 1. 概述

### 1.1 核心问题：同一行为，不同风险

在安全检测中，一个关键原则是：**行为的威胁等级取决于其执行上下文**。

```
同一命令：whoami

┌─────────────────────────────┐    ┌─────────────────────────────┐
│        🖥️ 主机环境           │    │        📦 容器环境           │
├─────────────────────────────┤    ├─────────────────────────────┤
│                             │    │                             │
│  $ whoami                   │    │  $ whoami                   │
│  root                       │    │  root                       │
│                             │    │                             │
│  ✅ 正常运维操作             │    │  ⚠️ 高度可疑！               │
│  管理员日常使用              │    │  容器内极少需要此命令        │
│  风险等级：低                │    │  可能为入侵后侦察行为       │
│                             │    │  风险等级：中                │
└─────────────────────────────┘    └─────────────────────────────┘
```

**为什么会有这种差异？**

- **主机**是通用计算环境，管理员经常执行各种系统命令进行运维管理
- **容器**是单一用途执行环境，设计上只运行特定的应用进程（如 nginx、node），不应该出现交互式管理操作

这种差异是理解本文所有内容的基础。

### 1.2 本文目标

本文通过 Tracee 的签名系统实现，系统性地分析：

1. 主机和容器在检测**机制层面**的一致性（共享内核 eBPF hook）
2. 主机和容器在检测**策略层面**的差异性（不同的告警阈值和规则）
3. 如何通过一个签名（`DangerousCommandExecution`）同时覆盖两种场景

---

## 2. 底层检测机制对比

### 2.1 eBPF Hook 点完全一致

Tracee 的检测能力来自 eBPF 程序在内核中的 hook 点。由于容器与宿主机**共享同一内核**，所有 eBPF hook 点对两者完全一致：

```
┌─────────────────────────────────────────────────────────────┐
│                      用户空间                                │
│                                                             │
│  ┌──────────────┐   ┌──────────────┐   ┌──────────────┐   │
│  │  主机进程     │   │ 容器A (nginx)│   │ 容器B (redis)│   │
│  │  (sshd,      │   │              │   │              │   │
│  │   systemd)   │   │              │   │              │   │
│  └──────┬───────┘   └──────┬───────┘   └──────┬───────┘   │
│         │                  │                   │           │
├─────────┼──────────────────┼───────────────────┼───────────┤
│         │        Linux 内核 (共享)              │           │
│         ▼                  ▼                   ▼           │
│  ┌─────────────────────────────────────────────────────┐   │
│  │              系统调用入口                             │   │
│  │    tracepoint/syscalls/sys_enter_execve              │   │
│  │    ────────────────────────────────                  │   │
│  │              eBPF Hook ← 完全相同的 hook 点          │   │
│  │              无论来自主机还是容器                     │   │
│  └─────────────────────────────────────────────────────┘   │
│                           │                                 │
│                           ▼                                 │
│  ┌─────────────────────────────────────────────────────┐   │
│  │              Tracee eBPF 程序                        │   │
│  │    提取 cgroup_id → 判断来源 → 输出事件              │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

**关键 hook 点示例**（参见 [本地提权检测文档](local-privilege-escalation-detection.md) 1.1 节）：

| Hook 类型 | Hook 点 | 捕获能力 | 主机/容器 |
|-----------|---------|---------|-----------|
| Tracepoint | `sched_process_exec` | 进程执行 | 完全相同 |
| Kprobe | `security_file_open` | 文件打开 | 完全相同 |
| Kprobe | `security_socket_connect` | 网络连接 | 完全相同 |
| Tracepoint | `sys_enter_setuid` | 权限变更 | 完全相同 |
| LSM hook | `security_bprm_check` | 执行权限检查 | 完全相同 |

### 2.2 差异在上层

既然底层 hook 完全一致，主机与容器的检测差异体现在三个上层维度：

```
        底层完全一致                    上层产生差异
  ┌──────────────────┐    ┌─────────────────────────────────┐
  │                  │    │  1. 事件来源标注                  │
  │  eBPF Hook 点    │───►│     cgroup_id → container/host   │
  │  (内核态)        │    │                                  │
  │                  │    │  2. 行为基线                      │
  │  所有进程        │    │     主机：宽泛   容器：严格       │
  │  经过同一 hook   │    │                                  │
  │                  │    │  3. 告警策略                      │
  │                  │    │     Origin 过滤 + 条件分支        │
  └──────────────────┘    └─────────────────────────────────┘
```

---

## 3. 事件来源区分机制

### 3.1 核心：cgroup_id 与 containers_map

Tracee 在 eBPF 层面通过 cgroup_id 判断事件来源，在用户空间通过容器信息查找表完成容器识别。

**eBPF 层面** — 获取 cgroup_id（参见 [容器集成文档](06-container-integration.md) 1.2 节）：

```c
// pkg/ebpf/c/common/context.h
// 每个事件都会携带 cgroup_id
u64 cgroup_id = bpf_get_current_cgroup_id();
```

**eBPF Map** — containers_map（定义于 `pkg/ebpf/c/maps.h`）：

```c
// containers_map: cgroup_id -> container_info
// 用于在 eBPF 层面判断事件是否来自容器
BPF_HASH(containers_map, u32, u8);
```

**用户空间** — 容器管理器（参见 [容器集成文档](06-container-integration.md) 1.3 节）：

```go
// pkg/containers/containers.go
type Manager struct {
    cgroupsMap   map[uint32]CgroupDir    // cgroup ID → 目录信息
    containerMap map[string]Container     // 容器 ID → 容器详情
    enricher     runtime.Service          // Docker/containerd/CRI-O 查询
}
```

### 3.2 事件流转路径

```
事件产生                    eBPF 层                 用户空间
────────                   ────────                ─────────

容器中执行 whoami
    │
    ▼
sched_process_exec ──► eBPF 程序获取：
触发                    • pid, uid, argv...
                        • cgroup_id = 12345
                              │
                              ▼
                        查询 containers_map[12345]
                              │
                        ┌─────┴─────┐
                        │ 存在(容器) │
                        └─────┬─────┘
                              │
                              ▼
                        事件输出到 perf buffer
                        携带 cgroup_id
                              │
                              ▼
                        Tracee 用户空间解析 ──► trace.Event{
                                                 ContainerID: "abc123...",
                                                 Container: Container{
                                                   ID: "abc123...",
                                                   Name: "web-app",
                                                 },
                                                 ProcessName: "whoami",
                                               }
                                                      │
                                                      ▼
                                               签名引擎分发事件
                                               签名通过 Container.ID
                                               判断来源
```

### 3.3 签名中的判断方式

在签名代码中，判断事件来自容器还是主机非常简单：

```go
func (sig *DangerousCommandExecution) OnEvent(event protocol.Event) error {
    eventObj, ok := event.Payload.(trace.Event)
    // ...

    // Container.ID 非空 = 容器事件，空 = 主机事件
    isContainer := eventObj.Container.ID != ""

    if isContainer {
        // 容器环境：更严格的检测策略
    } else {
        // 主机环境：仅检测高危行为
    }
}
```

---

## 4. 行为基线差异

### 4.1 主机行为基线：宽泛

主机是通用操作系统环境，正常运维中会出现大量系统管理操作：

```
主机上的正常行为 (不应告警):

👤 管理员运维
   $ whoami / id / hostname / uname -a
   $ ps aux / top / netstat -tlnp
   $ cat /etc/passwd / cat /etc/hosts
   $ nmap 192.168.1.0/24    (安全扫描)
   $ curl http://internal-api/health

⚙️ 系统服务
   systemd 管理各种守护进程
   cron 执行定时任务
   package manager 安装软件

🔧 自动化工具
   Ansible/Chef/Puppet 执行配置管理
   CI/CD agent 运行构建任务
```

### 4.2 容器行为基线：严格

容器遵循**单一职责**原则，正常运行时行为高度可预测：

```
容器的正常行为 (高度受限):

📦 Nginx 容器
   仅运行: nginx master + worker 进程
   仅监听: 80/443 端口
   仅访问: /etc/nginx/, /var/log/nginx/, /usr/share/nginx/html/
   不应出现: shell, whoami, curl, wget, nc, nmap ...

📦 Redis 容器
   仅运行: redis-server 进程
   仅监听: 6379 端口
   仅访问: /data/, /etc/redis/
   不应出现: 任何非 redis 进程

📦 Node.js 应用容器
   仅运行: node 进程
   仅监听: 应用端口 (如 3000)
   不应出现: shell, 系统探测命令, 网络扫描工具
```

### 4.3 基线差异对比表

| 行为类别 | 主机基线 | 容器基线 | 差异原因 |
|---------|---------|---------|---------|
| 用户信息查询 (`whoami`, `id`) | ✅ 正常 — 运维日常 | ⚠️ 可疑 — 无正当理由 | 容器内不需要交互式身份确认 |
| 系统信息收集 (`uname`, `hostname`) | ✅ 正常 — 排障常用 | ⚠️ 可疑 — 可能是侦察 | 容器不需要了解宿主机信息 |
| 网络扫描 (`nmap`, `masscan`) | ✅ 正常 — 安全审计 | 🔴 高危 — 横向移动前兆 | 容器不应有网络扫描需求 |
| 密码文件读取 (`cat /etc/passwd`) | ✅ 正常 — 管理操作 | ⚠️ 可疑 — 信息收集 | 容器内该文件无实际管理价值 |
| 反弹 Shell (`nc -e`, `bash -i`) | 🔴 高危 — 入侵行为 | 🔴 高危 — 入侵行为 | 无论在哪都是恶意行为 |
| 下载执行 (`curl .. \| bash`) | 🔴 高危 — 恶意下载 | 🔴 高危 — 恶意下载 | 下载并执行任意代码都很危险 |
| 包管理 (`apt install`, `yum`) | ✅ 正常 — 软件安装 | ⚠️ 可疑 — 不可变基础设施 | 生产容器不应安装新软件 |
| Shell 启动 (`bash`, `sh`) | ✅ 正常 — 脚本执行 | ⚠️ 取决于父进程 | Web 服务器生成 shell 可疑 |

---

## 5. 签名规则的 Origin 过滤

### 5.1 Origin 机制

Tracee 签名通过 `GetSelectedEvents()` 中的 `Origin` 字段控制事件过滤：

```go
type SignatureEventSelector struct {
    Source string  // 事件源，通常为 "tracee"
    Name   string  // 事件名称，如 "sched_process_exec"
    Origin string  // 来源过滤: "container" | "host" | "*"
}
```

| Origin 值 | 含义 | 签名引擎行为 |
|-----------|------|-------------|
| `"container"` | 仅容器事件 | 只将来自容器的事件分发给该签名 |
| `"host"` | 仅主机事件 | 只将来自主机的事件分发给该签名 |
| `"*"` | 所有事件 | 不做来源过滤，签名内部自行处理 |

### 5.2 现有签名 Origin 分布统计

对 `signatures/golang/` 下所有签名的 Origin 使用情况统计：

```
Origin 分布 (基于事件选择器数量):

  "container"  ████████████  12 个事件选择器
  "host"       █             1 个事件选择器
  "*"          ██████████████████████████████████  34 个事件选择器
```

**container-only 签名**（Origin: "container"）：

| 签名 | 说明 | 为什么限定容器 |
|------|------|---------------|
| `DockerAbuse` | Docker socket 滥用 | 从容器内访问 docker.sock 才是逃逸行为 |
| `CgroupReleaseAgentModification` | cgroup release_agent 修改 | 容器逃逸手法，主机上是正常管理 |
| `CgroupNotifyOnReleaseModification` | notify_on_release 修改 | 同上，配合 release_agent 逃逸 |
| `CorePatternModification` | core_pattern 修改 | 容器内修改属于逃逸，主机上可能是配置 |
| `DiskMount` | 磁盘挂载 | 容器内挂载宿主机磁盘 = 逃逸 |
| `DroppedExecutable` | 可执行文件投放 | 容器内出现新二进制文件高度可疑 |
| `K8sServiceAccountToken` | K8s 令牌窃取 | 容器内读取 token 可能是横向移动 |
| `KubernetesApiConnection` | K8s API 连接 | 容器内直连 API Server 可疑 |
| `ProcKcoreRead` | /proc/kcore 读取 | 容器内读取内核内存 = 信息泄露 |
| `SchedDebugRecon` | sched_debug 侦察 | 容器内读取调度信息 = 侦察行为 |
| `SystemRequestKeyConfigModification` | request_key 配置修改 | 容器内修改属于逃逸尝试 |

**host-only 签名**（Origin: "host"）：

| 签名 | 说明 | 为什么限定主机 |
|------|------|---------------|
| `ProcFopsHooking` | /proc 文件操作 hooking | 内核态 rootkit 行为，仅在主机层面有意义 |

**通配签名**（Origin: "*"）：

| 签名 | 说明 | 为什么不限定 |
|------|------|-------------|
| `StdioOverSocket` | 标准输入输出重定向到 socket | 反弹 Shell 在任何环境都危险 |
| `IllegitimateShell` | Web 服务器产生 shell | 无论在容器还是主机都可疑 |
| `LdPreload` | LD_PRELOAD 注入 | 代码注入在任何环境都危险 |
| `FilelessExecution` | 无文件执行 | memfd_create 执行在任何环境都可疑 |
| `PtraceCodeInjection` | ptrace 代码注入 | 进程注入在任何环境都危险 |
| ... | | |

### 5.3 设计意图分析

```
Origin 选择决策树:

  该行为是否仅在特定环境中异常？
  │
  ├─ 是，仅在容器中异常 ──► Origin: "container"
  │   例: Docker socket 访问（主机上可能是正常的 Docker 管理）
  │
  ├─ 是，仅在主机中异常 ──► Origin: "host"
  │   例: /proc fops hooking（容器内看不到此类事件）
  │
  └─ 否，在两种环境中都异常 ──► Origin: "*"
      │
      ├─ 两种环境策略相同 ──► OnEvent 中无需区分
      │   例: StdioOverSocket（反弹 Shell 总是危险）
      │
      └─ 两种环境策略不同 ──► OnEvent 中通过 Container.ID 区分
          例: DangerousCommandExecution（本文案例）
```

---

## 6. 案例分析：DangerousCommandExecution 签名

### 6.1 签名概览

**文件**: [`signatures/golang/dangerous_command_execution.go`](../signatures/golang/dangerous_command_execution.go)

```
签名 ID:       TRC-CUSTOM-001
签名名称:      Dangerous Command Execution
事件名称:      dangerous_command_execution
MITRE ATT&CK:  T1059 (Command and Scripting Interpreter)
严重等级:      2 (中)
事件源:        sched_process_exec, Origin: "*"
```

### 6.2 设计思路

该签名的核心创新在于：**使用一个签名同时覆盖两种环境，通过运行时判断采用不同的检测策略**。

```
                    sched_process_exec 事件
                            │
                            ▼
                ┌───────────────────────┐
                │  Container.ID != "" ? │
                └───────────┬───────────┘
                    │               │
                   Yes              No
                    │               │
                    ▼               ▼
           ┌──────────────┐  ┌──────────────┐
           │   容器策略     │  │   主机策略    │
           ├──────────────┤  ├──────────────┤
           │ ✅ 侦察命令   │  │ ❌ 侦察命令   │
           │   whoami, id  │  │   (忽略)      │
           │   hostname    │  │              │
           │   uname, nmap │  │              │
           │   cat passwd  │  │              │
           ├──────────────┤  ├──────────────┤
           │ ✅ 反弹Shell  │  │ ✅ 反弹Shell  │
           │   nc -e       │  │   nc -e      │
           │   socat exec  │  │   socat exec │
           │   curl|bash   │  │   curl|bash  │
           └──────────────┘  └──────────────┘
```

### 6.3 关键实现细节

**两类命令列表**：

```go
// 容器专用检测 — 这些命令在容器中不应该出现
containerOnlyCommands = []string{
    "whoami", "id", "hostname", "uname",  // 侦察
    "nmap", "masscan", "ncat",            // 网络探测
}

// 全局检测 — 无论在哪都是恶意行为
alwaysDangerousPatterns = []dangerousPattern{
    {processName: "nc",   argPatterns: []string{"-e"}},           // 反弹 Shell
    {processName: "socat", argPatterns: []string{"exec:"}},       // 反弹 Shell
    {processName: "bash", argPatterns: []string{"-i >& /dev/tcp"}}, // Bash 反弹 Shell
    {processName: "curl", argPatterns: []string{"|bash", "|sh"}}, // 下载并执行
    {processName: "wget", argPatterns: []string{"|bash", "|sh"}}, // 下载并执行
}
```

**环境判断逻辑**：

```go
// Origin: "*" 接收所有事件，在 OnEvent 中判断来源
isContainer := eventObj.Container.ID != ""

// 1. 先检查"始终危险"的模式（两种环境都检查）
for _, pattern := range sig.alwaysDangerousPatterns {
    // 匹配进程名 + 参数模式
}

// 2. 再检查"仅容器异常"的命令（只在容器环境检查）
if isContainer {
    for _, cmd := range sig.containerOnlyCommands {
        // 匹配进程名
    }
}
```

**Finding 中标注上下文**：

```go
sig.cb(&detect.Finding{
    SigMetadata: metadata,
    Event:       event,
    Data: map[string]interface{}{
        "context": "container",  // 或 "host"
    },
})
```

### 6.4 测试用例解读

测试文件 [`signatures/golang/dangerous_command_execution_test.go`](../signatures/golang/dangerous_command_execution_test.go) 覆盖了所有关键场景：

| # | 场景 | 命令 | 环境 | 期望结果 | 原因 |
|---|------|------|------|---------|------|
| 1 | 容器内侦察 | `whoami` | 容器 | ✅ 告警 | 容器内无正当理由 |
| 2 | 主机运维 | `whoami` | 主机 | ❌ 不告警 | 管理员日常操作 |
| 3 | 容器内反弹Shell | `nc -e /bin/bash` | 容器 | ✅ 告警 | 反弹Shell总是危险 |
| 4 | 主机反弹Shell | `nc -e /bin/bash` | 主机 | ✅ 告警 | 反弹Shell总是危险 |
| 5 | 容器正常命令 | `ls -la` | 容器 | ❌ 不告警 | 不在检测列表中 |
| 6 | 主机网络扫描 | `nmap -sV ...` | 主机 | ❌ 不告警 | 安全团队正常操作 |
| 7 | 容器网络扫描 | `nmap -sV ...` | 容器 | ✅ 告警 | 容器内扫描高度可疑 |
| 8 | 容器读密码文件 | `cat /etc/passwd` | 容器 | ✅ 告警 | 容器内信息收集 |
| 9 | 主机下载执行 | `curl ... \|bash` | 主机 | ✅ 告警 | 下载执行总是危险 |

**测试中模拟容器事件的方式**：

```go
// 容器事件 — 设置 Container.ID
trace.Event{
    EventName:   "sched_process_exec",
    ProcessName: "whoami",
    Container: trace.Container{
        ID: "abc123def456",     // 非空 = 容器
    },
    Args: []trace.Argument{{
        ArgMeta: trace.ArgMeta{Name: "argv"},
        Value:   interface{}([]string{"whoami"}),
    }},
}

// 主机事件 — Container 字段为零值
trace.Event{
    EventName:   "sched_process_exec",
    ProcessName: "whoami",
    // Container 未设置 → Container.ID == "" → 主机事件
    Args: []trace.Argument{{
        ArgMeta: trace.ArgMeta{Name: "argv"},
        Value:   interface{}([]string{"whoami"}),
    }},
}
```

---

## 7. 威胁模型对比表

### 7.1 按攻击阶段分类

以下是各类高危行为在主机与容器中的系统性风险对比（参考 MITRE ATT&CK 框架）：

#### 侦察阶段 (Discovery)

| 行为 | MITRE ID | 容器风险 | 主机风险 | 说明 |
|------|----------|---------|---------|------|
| `whoami` / `id` | T1033 | ⚠️ 中 | ✅ 低 | 容器内不需要确认身份 |
| `hostname` / `uname` | T1082 | ⚠️ 中 | ✅ 低 | 容器不需要宿主机信息 |
| `cat /etc/passwd` | T1087 | ⚠️ 中 | ✅ 低 | 容器内无用户管理需求 |
| `cat /proc/1/cgroup` | T1082 | 🔴 高 | ✅ 低 | 容器逃逸前的环境探测 |
| `mount` (查看挂载) | T1082 | ⚠️ 中 | ✅ 低 | 容器逃逸路径探索 |

#### 执行阶段 (Execution)

| 行为 | MITRE ID | 容器风险 | 主机风险 | 说明 |
|------|----------|---------|---------|------|
| `bash -i >& /dev/tcp` | T1059.004 | 🔴 高 | 🔴 高 | 反弹 Shell |
| `nc -e /bin/bash` | T1059 | 🔴 高 | 🔴 高 | 反弹 Shell |
| `python -c 'import socket...'` | T1059.006 | 🔴 高 | 🔴 高 | Python 反弹 Shell |
| `curl ... \| bash` | T1059 | 🔴 高 | 🔴 高 | 下载并执行 |
| Web 服务器产生 shell | T1190 | 🔴 高 | 🔴 高 | 已有 TRC-1016 检测 |

#### 横向移动 (Lateral Movement)

| 行为 | MITRE ID | 容器风险 | 主机风险 | 说明 |
|------|----------|---------|---------|------|
| `nmap` / `masscan` | T1046 | 🔴 高 | ⚠️ 中 | 容器无扫描需求 |
| 访问 K8s API Server | T1552 | 🔴 高 | ⚠️ 中 | 已有 TRC-1013 检测 |
| 访问 Docker Socket | T1068 | 🔴 高 | ⚠️ 中 | 已有 TRC-1019 检测 |

#### 持久化 (Persistence)

| 行为 | MITRE ID | 容器风险 | 主机风险 | 说明 |
|------|----------|---------|---------|------|
| 修改 crontab | T1053 | 🔴 高 | ⚠️ 中 | 已有 TRC-1027 检测 |
| LD_PRELOAD 注入 | T1574 | 🔴 高 | 🔴 高 | 已有 TRC-107 检测 |
| 修改 /etc/ld.so.preload | T1574 | 🔴 高 | 🔴 高 | 已有 TRC-107 检测 |
| 投放可执行文件 | T1105 | 🔴 高 | ⚠️ 中 | 已有 TRC-1022 检测（仅容器） |

#### 容器逃逸 (Container Escape)

| 行为 | MITRE ID | 容器风险 | 主机风险 | 说明 |
|------|----------|---------|---------|------|
| 修改 release_agent | T1611 | 🔴 高 | N/A | 已有 TRC-1022 检测 |
| 修改 notify_on_release | T1611 | 🔴 高 | N/A | 已有 TRC-1020 检测 |
| 挂载宿主机磁盘 | T1611 | 🔴 高 | N/A | 已有 TRC-1014 检测 |
| 读取 /proc/kcore | T1611 | 🔴 高 | N/A | 已有 TRC-1031 检测 |

### 7.2 检测策略选择指南

```
新签名的 Origin 选择:

  行为是否涉及容器逃逸机制？
  │
  ├─ Yes ──► Origin: "container"
  │         (release_agent, mount escape, Docker socket 等)
  │
  └─ No
     │
     行为是否仅在内核/主机层面可观测？
     │
     ├─ Yes ──► Origin: "host"
     │         (内核 rootkit, /proc hook 等)
     │
     └─ No
        │
        两种环境的检测逻辑是否完全相同？
        │
        ├─ Yes ──► Origin: "*", OnEvent 中不区分
        │         (反弹 Shell, LD_PRELOAD 等)
        │
        └─ No ──► Origin: "*", OnEvent 中根据 Container.ID 分支
                  (本文 DangerousCommandExecution 的模式)
```

---

## 8. 关联文档

| 文档 | 关联内容 |
|------|---------|
| [容器逃逸技术调研](container-escape-research.md) | 容器逃逸攻击手法和 Tracee 检测实现（3.1 节检测架构图） |
| [本地提权检测](local-privilege-escalation-detection.md) | eBPF Hook 点选择和权限变更检测（1.1-1.3 节 hook 点对比） |
| [容器集成](06-container-integration.md) | 容器识别机制：CGroup 检测、容器 ID 提取、运行时丰富化 |
| [签名引擎](signature-engine.md) | 签名引擎架构、接口定义、签名生命周期 |
| [检测设计方法论](detection-design-methodology.md) | 签名设计的通用方法论和最佳实践 |
| [实验：容器逃逸](lab-03-container-escape.md) | 容器逃逸检测的动手实验 |
| [实验：提权检测](lab-01-privilege-escalation.md) | 提权检测的动手实验 |

---

> **总结**：主机和容器共享相同的内核 eBPF Hook 点，检测差异不在底层捕获能力，而在**上层的行为基线和告警策略**。`DangerousCommandExecution` 签名通过 `Origin: "*"` + `Container.ID` 判断的模式，展示了如何用一个签名优雅地覆盖两种环境的差异化检测需求。
