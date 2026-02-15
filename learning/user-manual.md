# Tracee 使用手册

完整的 Tracee 运行时安全和取证工具使用指南。

---

## 目录

- [1. Tracee 简介](#1-tracee-简介)
- [2. 安装部署](#2-安装部署)
- [3. 快速开始](#3-快速开始)
- [4. 策略配置](#4-策略配置)
- [5. 事件追踪](#5-事件追踪)
- [6. 输出配置](#6-输出配置)
- [7. 高级功能](#7-高级功能)
- [8. 常见使用场景](#8-常见使用场景)
- [9. 性能优化](#9-性能优化)
- [10. 故障排查](#10-故障排查)

---

## 1. Tracee 简介

### 1.1 什么是 Tracee？

Tracee 是一个开源的 **Linux 运行时安全和取证工具**，使用 eBPF 技术进行系统监控和威胁检测。

**核心理念：Everything is an Event**

与其他工具不同，Tracee 将所有数据统一为事件：
- 底层系统调用 → 事件
- 网络活动 → 事件
- 安全检测 → 事件
- 容器操作 → 事件

这种统一的视角使得：
- ✅ 可以在同一策略中组合不同类型的事件
- ✅ 跨多个数据源构建复杂的检测逻辑
- ✅ 保持对系统行为的一致视图

### 1.2 主要特性

#### 🎯 丰富的事件覆盖

- **400+ 系统调用**：全面的系统监控
- **网络事件**：DNS、HTTP、数据包分析
- **安全事件**：预置威胁检测签名
- **容器事件**：原生 Kubernetes 集成

#### 🛠️ 简单而强大

- **直观的 YAML 语法**：几行配置即可创建强大的策略
- **灵活的目标定位**：从全局到容器级别的精细控制
- **易于部署**：支持开发和生产环境

#### 🔍 取证能力

- **网络流量捕获**：详细的网络分析
- **二进制文件采集**：恶意软件调查
- **内存转储**：高级取证分析
- **文件制品**：合规性和审计

#### 🔗 统一架构

- 所有事件通过相同的处理管道
- 策略可以引用任意事件类型组合
- 自定义签名与内置事件自然集成
- 单一配置控制整个系统

### 1.3 适用场景

| 场景 | 说明 |
|-----|------|
| **威胁检测** | 检测可疑的系统活动和安全威胁 |
| **取证分析** | 深入调查系统和容器事件 |
| **合规审计** | 监控和记录系统活动以满足合规要求 |
| **性能监控** | 追踪系统调用以分析性能问题 |
| **容器安全** | Kubernetes 和容器环境的安全监控 |
| **行为分析** | 理解应用程序和系统的运行时行为 |

---

## 2. 安装部署

### 2.1 系统要求

#### 最低要求

- **操作系统**：Linux Kernel 5.2+ （推荐 5.8+）
- **架构**：x86_64 或 ARM64
- **内存**：至少 512MB 可用内存
- **权限**：需要 root 或 CAP_SYS_ADMIN 权限

#### eBPF 支持检查

```bash
# 检查内核版本
uname -r

# 检查 eBPF 支持
zgrep CONFIG_BPF /proc/config.gz

# 检查 BTF 支持（推荐）
ls /sys/kernel/btf/vmlinux
```

#### 容器环境要求

如果在容器中运行 Tracee：
- 需要 `--privileged` 模式或特定 capabilities
- 需要挂载 `/sys/kernel/debug`
- 需要访问主机的 `/proc` 和 `/etc/os-release`

### 2.2 安装方式

#### 方式 1：下载预编译二进制

```bash
# 下载最新版本
TRACEE_VERSION=$(curl -s https://api.github.com/repos/aquasecurity/tracee/releases/latest | grep '"tag_name"' | cut -d'"' -f4)
wget https://github.com/aquasecurity/tracee/releases/download/${TRACEE_VERSION}/tracee-${TRACEE_VERSION}-linux-amd64.tar.gz

# 解压
tar -xzf tracee-${TRACEE_VERSION}-linux-amd64.tar.gz

# 移动到系统路径
sudo mv tracee /usr/local/bin/

# 验证安装
tracee --version
```

#### 方式 2：使用 Docker

```bash
# 拉取镜像
docker pull aquasec/tracee:latest

# 基本运行（需要特权模式）
docker run --rm -it \
  --pid=host \
  --cgroupns=host \
  --privileged \
  -v /etc/os-release:/etc/os-release-host:ro \
  -v /var/run:/var/run:ro \
  aquasec/tracee:latest
```

#### 方式 3：Kubernetes Helm Chart

```bash
# 添加 Aqua Security Helm 仓库
helm repo add aqua https://aquasecurity.github.io/helm-charts/
helm repo update

# 安装 Tracee（DaemonSet 模式）
helm install tracee aqua/tracee \
  --namespace tracee-system \
  --create-namespace

# 查看状态
kubectl get pods -n tracee-system
```

#### 方式 4：从源码编译

```bash
# 克隆仓库
git clone https://github.com/aquasecurity/tracee.git
cd tracee

# 安装依赖
make prerequisites

# 编译
make

# 二进制位于 ./dist/tracee
./dist/tracee --version
```

### 2.3 验证安装

```bash
# 运行简单测试
sudo tracee --events openat --output table

# 在另一个终端执行命令触发事件
ls /tmp

# 应该看到 openat 事件输出
```

---

## 3. 快速开始

### 3.1 第一个命令

#### 追踪所有事件

```bash
# 警告：会产生大量输出！
sudo tracee
```

#### 追踪特定事件

```bash
# 追踪文件打开操作
sudo tracee --events openat

# 追踪多个事件
sudo tracee --events openat,close,read

# 追踪进程执行
sudo tracee --events execve
```

### 3.2 基本过滤

#### 按进程 ID 过滤

```bash
# 追踪特定 PID
sudo tracee --scope pid=1234 --events openat

# 追踪多个 PID
sudo tracee --scope pid=1234,5678 --events openat
```

#### 按用户 ID 过滤

```bash
# 只追踪 root 用户
sudo tracee --scope uid=0 --events execve

# 追踪非特权用户
sudo tracee --scope uid!=0 --events openat
```

#### 按容器过滤

```bash
# 只追踪容器内的事件
sudo tracee --scope container --events execve

# 追踪特定容器
sudo tracee --scope container=abc123def456 --events openat

# 排除容器（只追踪主机）
sudo tracee --scope not-container --events execve
```

### 3.3 输出格式

#### Table 格式（默认）

```bash
sudo tracee --events execve --output table
```

输出示例：
```
TIME             UID    EVENT       CONTAINER        COMMAND          ARGS
14:23:45.678901  0      execve      host             /bin/ls          ["-la", "/tmp"]
```

#### JSON 格式

```bash
sudo tracee --events execve --output json
```

输出示例：
```json
{
  "timestamp": 1680182976364916505,
  "processId": 1234,
  "userId": 0,
  "eventName": "execve",
  "args": [
    {"name": "pathname", "value": "/bin/ls"},
    {"name": "argv", "value": ["ls", "-la", "/tmp"]}
  ]
}
```

#### 保存到文件

```bash
# JSON 格式保存
sudo tracee --events execve --output json --output option:out-file=/tmp/tracee.json

# 同时输出到控制台和文件
sudo tracee --events execve --output json --output json:stdout --output json:/tmp/tracee.json
```

### 3.4 实用示例

#### 监控文件系统变化

```bash
# 监控 /etc 目录的修改
sudo tracee --events security_file_open \
  --scope global \
  --filter data.pathname=/etc/* \
  --output table
```

#### 检测可疑进程执行

```bash
# 监控 /tmp 目录下执行的程序
sudo tracee --events sched_process_exec \
  --filter data.pathname=/tmp/* \
  --output json
```

#### 追踪网络连接

```bash
# 监控所有 TCP 连接
sudo tracee --events net_packet_ipv4,security_socket_connect \
  --output table
```

#### 容器监控

```bash
# 监控所有容器的进程执行
sudo tracee --scope container \
  --events sched_process_exec,sched_process_exit \
  --output json
```

---

## 4. 策略配置

### 4.1 策略概念

**策略（Policy）** 定义了：
- 监控哪些工作负载（Scope）
- 追踪哪些事件（Rules）
- 应用哪些过滤器（Filters）

Tracee 最多支持加载 **64 个策略**。

### 4.2 策略文件结构

```yaml
apiVersion: tracee.aquasec.com/v1beta1
kind: Policy
metadata:
  name: my-policy                    # 策略名称（必需）
  annotations:
    description: My custom policy    # 策略描述（必需）
spec:
  scope:                             # 作用域（必需）
    - global
  rules:                             # 规则列表（必需）
    - event: execve
    - event: openat
      filters:
        - data.pathname=/tmp/*
```

### 4.3 定义作用域（Scope）

#### 全局作用域

```yaml
scope:
  - global  # 监控整个主机
```

#### 按 UID 过滤

```yaml
scope:
  - uid=0              # 只监控 root 用户
  - uid=1000,1001      # 监控多个用户（OR 逻辑）
  - uid!=0             # 排除 root 用户
```

#### 按 PID 过滤

```yaml
scope:
  - pid=1234           # 监控特定进程
  - pid>1000           # 监控 PID 大于 1000 的进程
  - pid!=1             # 排除 init 进程
```

#### 按进程名过滤

```yaml
scope:
  - comm=nginx         # 监控名为 nginx 的进程
  - comm=docker,containerd  # 监控多个进程
```

#### 容器过滤

```yaml
scope:
  - container          # 只监控容器
  - not-container      # 只监控主机进程
  - container=abc123def456  # 监控特定容器 ID
```

#### 按可执行文件过滤

```yaml
scope:
  - executable=/usr/bin/curl
  - executable=/tmp/*        # 监控 /tmp 下的所有可执行文件
```

#### 进程树过滤

```yaml
scope:
  - tree=1000          # 监控 PID 1000 及其所有子进程
  - follow             # 跟踪子进程
```

#### 命名空间过滤

```yaml
scope:
  - mntns=4026531840   # 按挂载命名空间
  - pidns=4026531836   # 按 PID 命名空间
  - uts=hostname123    # 按 UTS 命名空间（主机名）
```

### 4.4 定义规则（Rules）

#### 基本事件规则

```yaml
rules:
  - event: execve              # 进程执行
  - event: openat              # 文件打开
  - event: connect             # 网络连接
  - event: security_file_open  # LSM 安全钩子
```

#### 作用域过滤器

在特定事件上应用额外的作用域过滤：

```yaml
rules:
  - event: openat
    filters:
      - pid=1000               # 只追踪 PID 1000 的 openat
      - uid=0                  # 且必须是 root 用户
```

#### 数据过滤器

基于事件参数进行过滤：

```yaml
rules:
  - event: security_file_open
    filters:
      - data.pathname=/etc/*          # 路径匹配
      - data.flags=O_WRONLY,O_RDWR    # 写模式打开

  - event: security_socket_connect
    filters:
      - data.remote_addr=192.168.1.100  # 特定 IP
      - data.remote_port=443             # 特定端口
```

**如何找到数据字段名？**

方法 1：查看事件输出
```bash
sudo tracee --events security_file_open --output json | jq '.args[].name'
```

方法 2：查看[事件文档](../events/index.md)

#### 返回值过滤器

基于系统调用返回值过滤：

```yaml
rules:
  - event: openat
    filters:
      - retval<0          # 只记录失败的调用（错误）

  - event: close
    filters:
      - retval!=0         # 只记录失败的 close
```

#### 容器元数据过滤器

Kubernetes 和容器相关过滤：

```yaml
rules:
  - event: sched_process_exec
    filters:
      - containerImage=nginx:latest     # 特定镜像
      - containerName=my-container      # 容器名
      - podName=nginx-deployment-*      # Pod 名（支持通配符）
      - podNamespace=production         # K8s 命名空间
      - podUid=abc-123-def-456          # Pod UID
```

### 4.5 复杂策略示例

#### 监控敏感文件访问

```yaml
apiVersion: tracee.aquasec.com/v1beta1
kind: Policy
metadata:
  name: sensitive-files-monitor
  annotations:
    description: Monitor access to sensitive system files
spec:
  scope:
    - global
  rules:
    # 监控 /etc/passwd 的访问
    - event: security_file_open
      filters:
        - data.pathname=/etc/passwd
        - data.flags=O_WRONLY,O_RDWR

    # 监控 /etc/shadow 的访问（只读也记录）
    - event: security_file_open
      filters:
        - data.pathname=/etc/shadow

    # 监控 SSH 密钥访问
    - event: security_file_open
      filters:
        - data.pathname=/root/.ssh/*
        - data.pathname=/home/*/.ssh/*
```

#### 容器异常行为检测

```yaml
apiVersion: tracee.aquasec.com/v1beta1
kind: Policy
metadata:
  name: container-anomaly-detection
  annotations:
    description: Detect suspicious container activities
spec:
  scope:
    - container
  rules:
    # 检测容器中的进程执行
    - event: sched_process_exec

    # 检测容器逃逸尝试
    - event: security_bprm_check
      filters:
        - data.pathname=/bin/bash
        - data.pathname=/bin/sh

    # 监控容器内的网络连接
    - event: security_socket_connect
      filters:
        - data.remote_port=22      # SSH
        - data.remote_port=3389    # RDP
        - data.remote_port=4444    # 常见后门端口

    # 监控特权操作
    - event: cap_capable
```

#### 多策略配置

```yaml
# policy1.yaml - 监控所有主机活动
apiVersion: tracee.aquasec.com/v1beta1
kind: Policy
metadata:
  name: host-monitoring
  annotations:
    description: Monitor host system activities
spec:
  scope:
    - not-container
  rules:
    - event: sched_process_exec
    - event: security_file_open
      filters:
        - data.pathname=/etc/*

---
# policy2.yaml - 监控生产容器
apiVersion: tracee.aquasec.com/v1beta1
kind: Policy
metadata:
  name: production-containers
  annotations:
    description: Monitor production containers
spec:
  scope:
    - container
    - podNamespace=production
  rules:
    - event: sched_process_exec
    - event: security_socket_connect
    - event: dropped_executable
```

### 4.6 使用策略文件

#### 单个策略文件

```bash
sudo tracee --policy /path/to/policy.yaml
```

#### 多个策略文件

```bash
sudo tracee \
  --policy /path/to/policy1.yaml \
  --policy /path/to/policy2.yaml
```

#### 策略目录

```bash
# 加载目录下所有 YAML 文件
sudo tracee --policy /path/to/policies/
```

---

## 5. 事件追踪

### 5.1 事件类型

Tracee 支持以下类型的事件：

| 类型 | 说明 | 示例 |
|-----|------|------|
| **系统调用** | 400+ Linux 系统调用 | `openat`, `read`, `write`, `execve` |
| **生命周期** | 进程/容器生命周期 | `sched_process_exec`, `container_create` |
| **LSM 钩子** | Linux 安全模块钩子 | `security_file_open`, `security_socket_connect` |
| **网络** | 网络数据包和连接 | `net_packet_ipv4`, `net_packet_dns` |
| **安全** | 预置威胁检测 | `dropped_executable`, `hidden_kernel_module` |

### 5.2 常用事件

#### 进程监控

```bash
# 进程执行
sudo tracee --events sched_process_exec

# 进程退出
sudo tracee --events sched_process_exit

# 进程 fork
sudo tracee --events sched_process_fork

# 执行失败（有用于检测攻击尝试）
sudo tracee --events process_execute_failed
```

#### 文件操作

```bash
# 文件打开（系统调用级别）
sudo tracee --events openat,open

# 文件打开（安全钩子级别，更详细）
sudo tracee --events security_file_open

# 文件读写
sudo tracee --events vfs_read,vfs_write

# 文件删除
sudo tracee --events security_inode_unlink

# 文件重命名
sudo tracee --events security_inode_rename

# 文件修改检测（魔数变化）
sudo tracee --events magic_write
```

#### 网络监控

```bash
# TCP 连接
sudo tracee --events net_packet_ipv4,security_socket_connect

# DNS 查询和响应
sudo tracee --events net_packet_dns_request,net_packet_dns_response

# HTTP 请求
sudo tracee --events net_packet_http_request,net_packet_http_response

# ICMP 数据包
sudo tracee --events net_packet_icmp

# 网络流统计
sudo tracee --events net_flow_tcp_begin,net_flow_tcp_end
```

#### 容器事件

```bash
# 容器创建和删除
sudo tracee --events container_create,container_remove

# CGroup 操作
sudo tracee --events cgroup_mkdir,cgroup_rmdir

# 已存在的容器（启动时发现）
sudo tracee --events existing_container
```

#### 安全事件（检测签名）

```bash
# 检测所有安全威胁
sudo tracee --events dropped_executable,hidden_kernel_module,anti_debugging

# 容器逃逸尝试
sudo tracee --events container_escape

# 代码注入
sudo tracee --events code_injection

# 反调试技术
sudo tracee --events anti_debugging

# 内核模块加载
sudo tracee --events hidden_kernel_module_seeker
```

### 5.3 列出可用事件

```bash
# 列出所有事件
sudo tracee --events list

# 按类别过滤
sudo tracee --events list | grep syscalls
sudo tracee --events list | grep lsm
sudo tracee --events list | grep network
```

### 5.4 事件组合技巧

#### 检测恶意文件执行

```bash
# 监控从 /tmp 或 /dev/shm 执行的程序
sudo tracee \
  --events sched_process_exec \
  --filter data.pathname=/tmp/*,/dev/shm/* \
  --output json
```

#### 追踪完整的进程生命周期

```bash
sudo tracee \
  --events sched_process_fork,sched_process_exec,sched_process_exit \
  --scope tree=1234 \
  --output table
```

#### 网络连接审计

```bash
sudo tracee \
  --events security_socket_connect,net_packet_ipv4,net_packet_dns \
  --scope container \
  --output json
```

---

## 6. 输出配置

### 6.1 输出格式

#### Table 格式（人类可读）

```bash
sudo tracee --events execve --output table
```

**优点**：
- 易于阅读
- 适合实时监控
- 自动列对齐

**缺点**：
- 不适合程序解析
- 字段可能被截断

#### JSON 格式（机器可读）

```bash
sudo tracee --events execve --output json
```

**优点**：
- 完整的事件数据
- 易于程序解析
- 支持嵌套结构

**示例输出**：
```json
{
  "timestamp": 1680182976364916505,
  "threadStartTime": 1680179107675006774,
  "processorId": 0,
  "processId": 1234,
  "threadId": 1234,
  "parentProcessId": 1,
  "userId": 0,
  "eventName": "execve",
  "eventId": "59",
  "returnValue": 0,
  "args": [
    {"name": "pathname", "type": "const char*", "value": "/bin/ls"},
    {"name": "argv", "type": "const char**", "value": ["ls", "-la"]}
  ],
  "container": {
    "id": "abc123def456",
    "name": "my-container",
    "image": "nginx:latest"
  },
  "kubernetes": {
    "podName": "nginx-pod",
    "podNamespace": "default"
  }
}
```

#### GoTemplate 格式（自定义）

```bash
sudo tracee --events execve \
  --output gotemplate=/path/to/template.tmpl
```

模板示例（`template.tmpl`）：
```go
{{.Timestamp}},{{.ProcessID}},{{.EventName}},{{.Container.Name}}
```

#### Forward 格式（发送到远程）

```bash
# 发送到 HTTP endpoint
sudo tracee --events execve \
  --output webhook:http://example.com/events

# 发送到多个目标
sudo tracee --events execve \
  --output webhook:http://server1.com/events \
  --output webhook:http://server2.com/events
```

### 6.2 输出选项

#### 输出到文件

```bash
# JSON 输出到文件
sudo tracee --events execve \
  --output json \
  --output option:out-file=/var/log/tracee.json

# Table 输出到文件
sudo tracee --events execve \
  --output table \
  --output option:out-file=/var/log/tracee.log
```

#### 多目标输出

```bash
# 同时输出到控制台和文件
sudo tracee --events execve \
  --output json:stdout \
  --output json:/var/log/tracee.json

# 输出到文件并发送到 webhook
sudo tracee --events execve \
  --output json:/var/log/tracee.json \
  --output webhook:http://siem.example.com/events
```

#### 控制输出详细程度

```bash
# 解析参数（更详细）
sudo tracee --events execve \
  --output option:parse-arguments

# 只输出检测结果（过滤掉非威胁事件）
sudo tracee --events all-signatures \
  --output option:detect-only
```

#### 时间戳格式

```bash
# Unix 纳秒时间戳（默认）
sudo tracee --events execve --output json

# 相对时间
sudo tracee --events execve \
  --output option:relative-timestamp

# 无时间戳
sudo tracee --events execve \
  --output option:no-timestamp
```

### 6.3 日志配置

#### 日志级别

```bash
# Debug 日志
sudo tracee --log debug --events execve

# Info 日志（默认）
sudo tracee --log info --events execve

# Warning 日志
sudo tracee --log warn --events execve

# Error 日志
sudo tracee --log error --events execve
```

#### 日志输出

```bash
# 日志输出到文件
sudo tracee --log info \
  --log option:log-file=/var/log/tracee.log \
  --events execve

# JSON 格式日志
sudo tracee --log info \
  --log option:log-format=json \
  --events execve
```

### 6.4 配置文件输出

创建配置文件 `config.yaml`：

```yaml
output:
  # 输出格式
  - json

  # 输出选项
  options:
    parse-arguments: true
    out-file: /var/log/tracee/events.json

  # 多目标输出
  forward:
    - protocol: webhook
      url: http://siem.example.com/events
      headers:
        Authorization: "Bearer token123"

log:
  level: info
  file: /var/log/tracee/tracee.log
  format: json
```

使用配置文件：
```bash
sudo tracee --config /path/to/config.yaml --policy /path/to/policy.yaml
```

---

## 7. 高级功能

### 7.1 取证数据采集

#### 捕获网络数据包

```bash
# 捕获所有网络数据包到 PCAP 文件
sudo tracee \
  --events net_packet_ipv4 \
  --capture net \
  --output option:capture-dir=/tmp/tracee-captures
```

生成的文件：
```
/tmp/tracee-captures/
├── capture-<timestamp>-<pid>.pcap
└── metadata.json
```

#### 采集执行的二进制文件

```bash
# 捕获所有执行的二进制文件
sudo tracee \
  --events sched_process_exec \
  --capture exec \
  --output option:capture-dir=/tmp/tracee-captures
```

用途：
- 恶意软件样本采集
- 合规性审计
- 取证分析

#### 采集写入的文件

```bash
# 捕获写入到 /tmp 的文件
sudo tracee \
  --events vfs_write \
  --filter data.pathname=/tmp/* \
  --capture write \
  --output option:capture-dir=/tmp/tracee-captures
```

#### 内存转储

```bash
# 捕获进程内存
sudo tracee \
  --events sched_process_exec \
  --capture mem \
  --output option:capture-dir=/tmp/tracee-captures
```

### 7.2 自定义签名

#### 签名结构

创建自定义签名文件 `custom-signature.go`：

```go
package main

import (
    "fmt"
    "github.com/aquasecurity/tracee/signatures/helpers"
    "github.com/aquasecurity/tracee/types/detect"
    "github.com/aquasecurity/tracee/types/protocol"
    "github.com/aquasecurity/tracee/types/trace"
)

type SuspiciousBashUsage struct {
    cb       detect.SignatureHandler
}

func (sig *SuspiciousBashUsage) Init(ctx detect.SignatureContext) error {
    sig.cb = ctx.Callback
    return nil
}

func (sig *SuspiciousBashUsage) GetMetadata() (detect.SignatureMetadata, error) {
    return detect.SignatureMetadata{
        ID:          "CUSTOM-001",
        Version:     "1.0.0",
        Name:        "Suspicious Bash Usage",
        EventName:   "suspicious_bash_usage",
        Description: "Detects suspicious bash command execution",
        Tags:        []string{"linux", "container"},
        Properties: map[string]interface{}{
            "Severity":     3,
            "Category":     "execution",
            "Technique":    "T1059",
            "MITRE ATT&CK": "Command and Scripting Interpreter",
        },
    }, nil
}

func (sig *SuspiciousBashUsage) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
    return []detect.SignatureEventSelector{
        {Source: "tracee", Name: "sched_process_exec"},
    }, nil
}

func (sig *SuspiciousBashUsage) OnEvent(event protocol.Event) error {
    eventObj, ok := event.Payload.(trace.Event)
    if !ok {
        return fmt.Errorf("invalid event")
    }

    pathname, err := helpers.GetTraceeStringArgumentByName(eventObj, "pathname")
    if err != nil {
        return err
    }

    // 检测从 /tmp 执行的 bash
    if pathname == "/bin/bash" || pathname == "/bin/sh" {
        cwd, _ := helpers.GetTraceeStringArgumentByName(eventObj, "cwd")
        if cwd == "/tmp" || strings.HasPrefix(cwd, "/tmp/") {
            m, _ := sig.GetMetadata()
            sig.cb(&detect.Finding{
                SigMetadata: m,
                Event:       event,
                Data: map[string]interface{}{
                    "pathname": pathname,
                    "cwd":      cwd,
                },
            })
        }
    }

    return nil
}

func (sig *SuspiciousBashUsage) OnSignal(s detect.Signal) error {
    return nil
}

func (sig *SuspiciousBashUsage) Close() {}
```

#### 编译和使用签名

```bash
# 编译签名为插件
go build -buildmode=plugin -o custom-signature.so custom-signature.go

# 使用自定义签名
sudo tracee \
  --signatures-dir /path/to/signatures/ \
  --events all-signatures
```

### 7.3 数据源集成

#### 容器数据源

```yaml
# 配置容器运行时
apiVersion: tracee.aquasec.com/v1beta1
kind: Config
metadata:
  name: tracee-config
spec:
  containers:
    runtime-sockets:
      - /var/run/docker.sock
      - /var/run/containerd/containerd.sock
      - /var/run/crio/crio.sock
```

#### DNS 缓存数据源

Tracee 自动关联 DNS 查询和响应：

```bash
# 启用 DNS 缓存
sudo tracee \
  --events net_packet_dns,net_packet_ipv4 \
  --output json
```

输出会包含域名信息：
```json
{
  "eventName": "net_packet_ipv4",
  "args": [
    {"name": "dst", "value": "1.2.3.4"},
    {"name": "domain", "value": "example.com"}  // 从 DNS 缓存获取
  ]
}
```

#### 进程树数据源

Tracee 维护完整的进程树：

```bash
# 追踪进程树
sudo tracee \
  --events sched_process_exec \
  --scope tree=1234 \
  --output json
```

输出包含进程层次：
```json
{
  "processId": 5678,
  "parentProcessId": 1234,
  "threadId": 5678,
  "processTree": {
    "ancestors": [1, 100, 1234]
  }
}
```

### 7.4 性能调优

#### 限制 CPU 使用

```bash
# 使用 cgroups 限制 CPU
sudo cgcreate -g cpu:/tracee
sudo cgset -r cpu.shares=512 tracee
sudo cgexec -g cpu:tracee tracee --events execve
```

#### 限制内存使用

```bash
# 使用 cgroups 限制内存
sudo cgcreate -g memory:/tracee
sudo cgset -r memory.limit_in_bytes=512M tracee
sudo cgexec -g memory:tracee tracee --events execve
```

#### 调整 Perf Buffer 大小

```bash
# 增加 buffer 大小以减少事件丢失（默认 1024 页）
sudo tracee \
  --perf-buffer-size 4096 \
  --events execve
```

#### 启用事件采样

```bash
# 只采样 10% 的事件
sudo tracee \
  --events execve \
  --sampling 10
```

---

## 8. 常见使用场景

### 8.1 安全监控

#### 场景 1：检测容器逃逸

```yaml
apiVersion: tracee.aquasec.com/v1beta1
kind: Policy
metadata:
  name: container-escape-detection
  annotations:
    description: Detect container escape attempts
spec:
  scope:
    - container
  rules:
    # 检测 nsenter 使用
    - event: sched_process_exec
      filters:
        - data.pathname=/usr/bin/nsenter

    # 检测 unshare 使用
    - event: sched_process_exec
      filters:
        - data.pathname=/usr/bin/unshare

    # 检测 mount 到主机目录
    - event: security_sb_mount

    # 检测特权提升
    - event: cap_capable

    # 使用预置签名
    - event: container_escape
```

运行：
```bash
sudo tracee --policy container-escape.yaml --output json
```

#### 场景 2：检测反向 Shell

```yaml
apiVersion: tracee.aquasec.com/v1beta1
kind: Policy
metadata:
  name: reverse-shell-detection
  annotations:
    description: Detect reverse shell attempts
spec:
  scope:
    - global
  rules:
    # 检测 bash/sh 的网络连接
    - event: security_socket_connect
      filters:
        - comm=bash,sh,dash

    # 检测 nc (netcat) 使用
    - event: sched_process_exec
      filters:
        - data.pathname=/bin/nc,/usr/bin/nc,/bin/netcat

    # 检测 Python/Perl 反向 shell
    - event: sched_process_exec
      filters:
        - data.pathname=/usr/bin/python
        - data.argv=socket
```

#### 场景 3：检测 Rootkit

```bash
# 使用预置的 rootkit 检测签名
sudo tracee \
  --events hidden_kernel_module,hooked_syscalls,symbols_collision \
  --output json
```

### 8.2 合规审计

#### 场景 4：PCI-DSS 文件访问审计

```yaml
apiVersion: tracee.aquasec.com/v1beta1
kind: Policy
metadata:
  name: pci-dss-file-access
  annotations:
    description: Audit file access for PCI-DSS compliance
spec:
  scope:
    - global
  rules:
    # 审计敏感配置文件
    - event: security_file_open
      filters:
        - data.pathname=/etc/passwd
        - data.pathname=/etc/shadow
        - data.pathname=/etc/group
        - data.pathname=/etc/sudoers

    # 审计数据库配置
    - event: security_file_open
      filters:
        - data.pathname=/etc/mysql/*
        - data.pathname=/etc/postgresql/*

    # 审计应用配置
    - event: security_file_open
      filters:
        - data.pathname=/opt/app/config/*
```

#### 场景 5：用户行为审计

```yaml
apiVersion: tracee.aquasec.com/v1beta1
kind: Policy
metadata:
  name: user-activity-audit
  annotations:
    description: Audit user activities
spec:
  scope:
    - uid!=0  # 非 root 用户
  rules:
    # 记录所有命令执行
    - event: sched_process_exec

    # 记录文件操作
    - event: security_file_open
    - event: security_inode_unlink
    - event: security_inode_rename

    # 记录网络连接
    - event: security_socket_connect
```

### 8.3 故障排查

#### 场景 6：调试应用文件访问问题

```bash
# 追踪特定进程的所有文件操作
sudo tracee \
  --scope comm=myapp \
  --events openat,open,close,read,write \
  --output table
```

#### 场景 7：分析网络连接失败

```bash
# 追踪失败的网络连接
sudo tracee \
  --events connect \
  --filter retval!=0 \
  --output json | jq '.args'
```

#### 场景 8：性能分析

```bash
# 统计系统调用频率
sudo tracee \
  --events syscalls \
  --scope pid=1234 \
  --output json \
  | jq -r '.eventName' \
  | sort | uniq -c | sort -rn
```

### 8.4 容器安全

#### 场景 9：监控 Kubernetes Pod

```yaml
apiVersion: tracee.aquasec.com/v1beta1
kind: Policy
metadata:
  name: kubernetes-pod-monitoring
  annotations:
    description: Monitor specific Kubernetes pods
spec:
  scope:
    - podNamespace=production
    - podName=nginx-*
  rules:
    - event: sched_process_exec
    - event: security_file_open
    - event: security_socket_connect
    - event: dropped_executable
```

在 Kubernetes 中部署：
```bash
kubectl create configmap tracee-policies \
  --from-file=policy.yaml \
  -n tracee-system

kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: tracee
  namespace: tracee-system
spec:
  hostPID: true
  hostNetwork: true
  containers:
  - name: tracee
    image: aquasec/tracee:latest
    securityContext:
      privileged: true
    volumeMounts:
    - name: policies
      mountPath: /policies
    - name: var-run
      mountPath: /var/run
      readOnly: true
    command:
    - /tracee/tracee
    - --policy
    - /policies/policy.yaml
  volumes:
  - name: policies
    configMap:
      name: tracee-policies
  - name: var-run
    hostPath:
      path: /var/run
EOF
```

#### 场景 10：检测容器中的加密货币挖矿

```yaml
apiVersion: tracee.aquasec.com/v1beta1
kind: Policy
metadata:
  name: crypto-mining-detection
  annotations:
    description: Detect cryptocurrency mining in containers
spec:
  scope:
    - container
  rules:
    # 检测已知挖矿程序
    - event: sched_process_exec
      filters:
        - data.pathname=/xmrig
        - data.pathname=/minerd
        - data.pathname=/cpuminer

    # 检测连接到矿池
    - event: security_socket_connect
      filters:
        - data.remote_port=3333    # 常见矿池端口
        - data.remote_port=5555
        - data.remote_port=7777

    # 检测 stratum 协议
    - event: net_packet_http
      filters:
        - data.protocol=stratum
```

---

## 9. 性能优化

### 9.1 减少事件量

#### 使用精确的作用域

```bash
# ❌ 不好：全局监控所有事件
sudo tracee --events openat

# ✅ 好：只监控特定进程
sudo tracee --scope comm=nginx --events openat

# ✅ 更好：只监控特定容器
sudo tracee --scope container=abc123 --events openat
```

#### 使用数据过滤器

```bash
# ❌ 不好：捕获所有文件打开
sudo tracee --events security_file_open

# ✅ 好：只捕获特定目录
sudo tracee \
  --events security_file_open \
  --filter data.pathname=/etc/*
```

### 9.2 优化 eBPF 性能

#### 调整 Perf Buffer

```bash
# 默认：1024 页（4MB）
sudo tracee --events execve

# 高负载环境：增加 buffer
sudo tracee \
  --perf-buffer-size 4096 \
  --events execve

# 低内存环境：减小 buffer
sudo tracee \
  --perf-buffer-size 512 \
  --events execve
```

#### 禁用不需要的功能

```bash
# 禁用容器enrichment（如果不需要容器信息）
sudo tracee \
  --no-containers-enrich \
  --events execve

# 禁用进程树（如果不需要祖先信息）
sudo tracee \
  --no-process-tree \
  --events execve
```

### 9.3 资源限制

#### 使用 systemd 限制

创建 `/etc/systemd/system/tracee.service`：

```ini
[Unit]
Description=Tracee Runtime Security
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/tracee --policy /etc/tracee/policy.yaml
Restart=always

# 资源限制
CPUQuota=50%
MemoryLimit=512M
TasksMax=100

[Install]
WantedBy=multi-user.target
```

启动服务：
```bash
sudo systemctl daemon-reload
sudo systemctl enable tracee
sudo systemctl start tracee
```

### 9.4 性能监控

#### 查看 Tracee 统计信息

```bash
# 启用统计信息输出
sudo tracee \
  --events execve \
  --output json \
  --stats
```

#### 监控资源使用

```bash
# 监控 Tracee 进程
watch -n 1 'ps aux | grep tracee'

# 查看 CPU 和内存
top -p $(pidof tracee)

# 查看 eBPF map 使用情况
sudo bpftool map list
sudo bpftool map show id <map-id>
```

---

## 10. 故障排查

### 10.1 常见问题

#### 问题 1：Tracee 无法启动

**症状**：
```
ERROR failed to initialize tracee: permission denied
```

**解决方案**：
```bash
# 1. 确认以 root 运行
sudo tracee --events execve

# 2. 检查 capabilities
sudo setcap cap_sys_admin,cap_sys_resource=+eip /usr/local/bin/tracee

# 3. 检查 SELinux/AppArmor
sudo setenforce 0  # 临时禁用 SELinux
sudo aa-complain /usr/local/bin/tracee  # AppArmor
```

#### 问题 2：事件丢失

**症状**：
```
WARN events lost: 1234
```

**解决方案**：
```bash
# 1. 增加 Perf Buffer 大小
sudo tracee \
  --perf-buffer-size 4096 \
  --events execve

# 2. 减少监控事件
sudo tracee \
  --scope container \
  --events execve  # 只监控必要事件

# 3. 增加系统资源
# 编辑 /etc/sysctl.conf
kernel.perf_event_max_sample_rate = 10000
kernel.perf_event_mlock_kb = 8192
```

#### 问题 3：容器信息缺失

**症状**：
```
container: {}  // 容器字段为空
```

**解决方案**：
```bash
# 1. 检查容器运行时 socket
ls -l /var/run/docker.sock
ls -l /var/run/containerd/containerd.sock

# 2. 挂载 socket（Docker 环境）
docker run -v /var/run/docker.sock:/var/run/docker.sock ...

# 3. 检查权限
sudo chmod 666 /var/run/docker.sock  # 临时解决

# 4. 显式指定运行时 socket
sudo tracee \
  --runtime-sockets /var/run/docker.sock \
  --events execve
```

#### 问题 4：高 CPU 使用率

**诊断**：
```bash
# 查看最频繁的事件
sudo tracee --events all --output json \
  | jq -r '.eventName' \
  | sort | uniq -c | sort -rn | head -10
```

**解决方案**：
```bash
# 1. 减少监控范围
sudo tracee --scope container --events execve

# 2. 使用更精确的过滤器
sudo tracee \
  --scope comm=nginx \
  --events openat \
  --filter data.pathname=/etc/*

# 3. 启用采样
sudo tracee --sampling 10 --events all
```

### 10.2 调试模式

#### 启用详细日志

```bash
# Debug 级别日志
sudo tracee \
  --log debug \
  --events execve

# 输出到文件
sudo tracee \
  --log debug \
  --log option:log-file=/tmp/tracee-debug.log \
  --events execve
```

#### 检查 eBPF 程序

```bash
# 列出加载的 eBPF 程序
sudo bpftool prog list | grep tracee

# 查看程序详情
sudo bpftool prog show id <prog-id>

# 查看程序统计信息
sudo bpftool prog show id <prog-id> --json | jq '.run_time_ns'
```

#### 检查 BPF Maps

```bash
# 列出所有 maps
sudo bpftool map list | grep tracee

# 查看 map 内容
sudo bpftool map dump id <map-id>

# 查看容器 map
sudo bpftool map dump name containers_map
```

### 10.3 获取帮助

#### 社区支持

- **GitHub Issues**：https://github.com/aquasecurity/tracee/issues
- **Slack**：https://slack.aquasec.com/
- **文档**：https://aquasecurity.github.io/tracee/

#### 报告 Bug

提供以下信息：
```bash
# 1. 系统信息
uname -a
cat /etc/os-release

# 2. Tracee 版本
tracee --version

# 3. 内核配置
zgrep CONFIG_BPF /proc/config.gz
zgrep CONFIG_DEBUG_INFO_BTF /proc/config.gz

# 4. 完整日志
sudo tracee --log debug --events execve 2>&1 | tee tracee.log

# 5. 策略文件
cat policy.yaml
```

---

## 附录 A：命令行参数速查

### 常用参数

```bash
# 基本用法
tracee [options] --events <events> --scope <scope>

# 事件选择
--events <event-list>          # 事件列表，逗号分隔
--events list                  # 列出所有可用事件

# 作用域过滤
--scope <scope-expression>     # 作用域表达式
--filter <filter-expression>   # 数据过滤器

# 策略文件
--policy <file>                # 策略 YAML 文件
--policy <dir>                 # 策略目录

# 输出配置
--output <format>              # 输出格式：table/json/gotemplate
--output option:<key>=<value>  # 输出选项
--log <level>                  # 日志级别：debug/info/warn/error

# 性能调优
--perf-buffer-size <pages>     # Perf buffer 大小（页）
--sampling <percentage>        # 采样百分比
--no-containers-enrich         # 禁用容器信息enrichment
--no-process-tree              # 禁用进程树

# 取证功能
--capture <types>              # 捕获类型：net/exec/write/mem
--capture-dir <dir>            # 捕获文件目录

# 其他
--config <file>                # 配置文件
--help                         # 帮助信息
--version                      # 版本信息
```

---

## 附录 B：事件类别速查

### 系统调用（示例）

```
openat, open, close, read, write, execve, fork, clone,
socket, connect, bind, listen, accept, sendto, recvfrom
```

### 生命周期事件

```
sched_process_exec      # 进程执行
sched_process_fork      # 进程 fork
sched_process_exit      # 进程退出
container_create        # 容器创建
container_remove        # 容器删除
cgroup_mkdir            # CGroup 创建
cgroup_rmdir            # CGroup 删除
```

### LSM 安全钩子

```
security_file_open         # 文件打开
security_file_mprotect     # 内存保护修改
security_socket_connect    # Socket 连接
security_socket_bind       # Socket 绑定
security_bprm_check        # 二进制检查
security_inode_unlink      # 文件删除
security_inode_rename      # 文件重命名
```

### 网络事件

```
net_packet_ipv4            # IPv4 数据包
net_packet_ipv6            # IPv6 数据包
net_packet_dns             # DNS 查询/响应
net_packet_http            # HTTP 请求/响应
net_packet_icmp            # ICMP 数据包
net_flow_tcp_begin         # TCP 流开始
net_flow_tcp_end           # TCP 流结束
```

### 安全检测事件

```
dropped_executable         # 可疑可执行文件
hidden_kernel_module       # 隐藏内核模块
code_injection             # 代码注入
anti_debugging             # 反调试
container_escape           # 容器逃逸
privilege_escalation       # 权限提升
```

---

## 附录 C：策略示例库

可以在以下位置找到更多策略示例：

- Tracee 仓库：`examples/policies/`
- 官方文档：https://aquasecurity.github.io/tracee/latest/docs/policies/
- 社区贡献：https://github.com/aquasecurity/tracee/tree/main/examples

### 常用策略模板

#### 1. 最小化监控（低开销）

```yaml
apiVersion: tracee.aquasec.com/v1beta1
kind: Policy
metadata:
  name: minimal-monitoring
  annotations:
    description: Minimal security monitoring with low overhead
spec:
  scope:
    - container
  rules:
    - event: dropped_executable
    - event: container_escape
    - event: privilege_escalation
```

#### 2. 全面监控（高详细度）

```yaml
apiVersion: tracee.aquasec.com/v1beta1
kind: Policy
metadata:
  name: comprehensive-monitoring
  annotations:
    description: Comprehensive monitoring for security analysis
spec:
  scope:
    - global
  rules:
    - event: sched_process_exec
    - event: security_file_open
    - event: security_socket_connect
    - event: net_packet_dns
    - event: all-signatures
```

#### 3. 合规审计模板

```yaml
apiVersion: tracee.aquasec.com/v1beta1
kind: Policy
metadata:
  name: compliance-audit
  annotations:
    description: Compliance audit for regulations
spec:
  scope:
    - global
  rules:
    - event: security_file_open
      filters:
        - data.pathname=/etc/passwd
        - data.pathname=/etc/shadow
        - data.pathname=/etc/sudoers
    - event: sched_process_exec
    - event: security_socket_connect
```

---

## 结语

Tracee 是一个强大而灵活的运行时安全工具。通过合理配置策略和过滤器，你可以：

- ✅ 实时检测安全威胁
- ✅ 进行深度取证分析
- ✅ 满足合规审计要求
- ✅ 监控容器和 Kubernetes 环境
- ✅ 自定义检测规则

**推荐学习路径：**

1. 从简单的 `--events execve` 开始
2. 学习使用作用域和过滤器
3. 创建自己的策略文件
4. 探索高级功能（取证、自定义签名）
5. 在生产环境中部署

**更多资源：**

- 📚 官方文档：https://aquasecurity.github.io/tracee/
- 💻 GitHub 仓库：https://github.com/aquasecurity/tracee
- 💬 Slack 社区：https://slack.aquasec.com/
- 📝 博客文章：https://blog.aquasec.com/tag/tracee

祝你使用愉快！🎉
