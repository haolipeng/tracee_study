# 本地提权技术调研文档

> 文档版本：1.0
> 创建日期：2026-02-03
> 作者：Security Research Team

---

## 目录

1. [概述](#1-概述)
2. [本地提权攻击手法](#2-本地提权攻击手法)
3. [本地提权检测方法](#3-本地提权检测方法)
4. [Tracee检测实现分析](#4-tracee检测实现分析)
5. [高危Capabilities详解](#5-高危capabilities详解)
6. [检测策略与配置](#6-检测策略与配置)
7. [总结与建议](#7-总结与建议)
8. [参考资料](#8-参考资料)

---

## 1. 概述

### 1.1 什么是本地提权

本地提权（Local Privilege Escalation，简称 LPE）是指攻击者在已获得目标系统低权限访问的情况下，通过利用系统漏洞、配置错误或��计缺陷，将自身权限提升至更高级别（通常是 root 或 SYSTEM 权限）的攻击技术。

本地提权是攻击链中的关键环节，通常发生在以下场景：
- 攻击者通过 Web 漏洞获得了低权限 shell
- 内部人员试图突破权限边界
- 恶意软件试图获取更高权限以实现持久化
- 容器逃逸攻击

### 1.2 MITRE ATT&CK 框架分类

在 MITRE ATT&CK 框架中，本地提权相关技术主要归类于 **Privilege Escalation (TA0004)** 战术，包含以下主要技术：

| 技术 ID | 技术名称 | 描述 |
|---------|---------|------|
| T1548 | Abuse Elevation Control Mechanism | 滥用权限提升控制机制 |
| T1548.001 | Setuid and Setgid | 利用 SUID/SGID 位 |
| T1548.002 | Bypass User Account Control | 绕过 UAC（Windows） |
| T1548.003 | Sudo and Sudo Caching | 利用 Sudo 配置 |
| T1068 | Exploitation for Privilege Escalation | 利用漏洞提权 |
| T1055 | Process Injection | 进程注入 |
| T1611 | Escape to Host | 容器逃逸 |
| T1547.006 | Kernel Modules and Extensions | 内核模块加载 |
| T1574.006 | Dynamic Linker Hijacking | 动态链接器劫持 |

### 1.3 Linux 权限模型

理解本地提权需要首先了解 Linux 的权限模型：

**传统 Unix 权限模型**：
- UID/GID：用户和组标识符
- EUID/EGID：有效用户和组 ID（决定实际权限）
- SUID/SGID：保存的用户和组 ID
- FSUID/FSGID：文件系统操作使用的 ID

**Linux Capabilities**：
- 从 Linux 2.2 开始引入
- 将 root 权限细分为 40+ 个独立的能力
- 允许进程拥有部分特权而非全部 root 权限
- 包括：CAP_INHERITABLE、CAP_PERMITTED、CAP_EFFECTIVE、CAP_BSET、CAP_AMBIENT

**凭证结构（struct cred）**：
```c
struct cred {
    kuid_t      uid;            // 真实 UID
    kgid_t      gid;            // 真实 GID
    kuid_t      suid;           // 保存的 UID
    kgid_t      sgid;           // 保存的 GID
    kuid_t      euid;           // 有效 UID
    kgid_t      egid;           // 有效 GID
    kuid_t      fsuid;          // 文件系统 UID
    kgid_t      fsgid;          // 文件系统 GID
    kernel_cap_t cap_inheritable;   // 可继承能力
    kernel_cap_t cap_permitted;     // 允许的能力
    kernel_cap_t cap_effective;     // 有效能力
    kernel_cap_t cap_bset;          // 能力边界集
    kernel_cap_t cap_ambient;       // 环境能力
    // ...
};
```

---

## 2. 本地提权攻击手法

### 2.1 SUID/SGID 滥用

**原理**：
SUID（Set User ID）位允许用户以文件所有者的权限执行程序。当 root 拥有的可执行文件设置了 SUID 位，任何用户执行它时都会以 root 权限运行。

**攻击向量**：
1. **已知 SUID 二进制利用**：利用 find、vim、python 等设置了 SUID 位的程序逃逸
2. **自定义 SUID 程序漏洞**：利用开发者编写的 SUID 程序中的缓冲区溢出、命令注入等漏洞
3. **环境变量注入**：通过 PATH、LD_PRELOAD 等环境变量影响 SUID 程序行为

**常见可利用的 SUID 程序**（GTFOBins）：
```
/usr/bin/find
/usr/bin/vim
/usr/bin/python
/usr/bin/perl
/usr/bin/bash
/usr/bin/nmap (旧版本)
/usr/bin/awk
```

**MITRE ATT&CK ID**：T1548.001

### 2.2 Sudo 配置错误

**原理**：
Sudo 允许管理员授予用户以其他用户（通常是 root）身份执行命令的权限。配置不当会导致权限提升。

**攻击向量**：
1. **通配符滥用**：`user ALL=(ALL) /usr/bin/vim *` 允许编辑任意文件
2. **NOPASSWD 配置**：允许无密码执行特权命令
3. **可写脚本执行**：用户有权执行可写的脚本文件
4. **LD_PRELOAD 保留**：env_keep 保留了危险的环境变量
5. **Sudo 版本漏洞**：如 CVE-2021-3156 (Baron Samedit)

**危险配置示例**：
```
# 危险：允许执行任意 shell 命令
user ALL=(root) /usr/bin/vim

# 危险：通配符可被利用
user ALL=(root) /usr/bin/python /opt/scripts/*.py

# 危险：保留 LD_PRELOAD
Defaults env_keep += "LD_PRELOAD"
```

**MITRE ATT&CK ID**：T1548.003

### 2.3 Linux Capabilities 滥用

**原理**：
Capabilities 是 Linux 将 root 权限细分后的产物。某些 Capability 可被滥用获得完整 root 权限。

**高危 Capabilities**：

| Capability | 风险 | 利用方式 |
|------------|------|----------|
| CAP_SYS_ADMIN | 极高 | 挂载文件系统、修改内核参数、加载 BPF 等 |
| CAP_SYS_MODULE | 极高 | 加载恶意内核模块 |
| CAP_SYS_PTRACE | 高 | 调试并注入任意进程 |
| CAP_DAC_OVERRIDE | 高 | 绕过文件权限检查 |
| CAP_DAC_READ_SEARCH | 高 | 读取任意文件 |
| CAP_SETUID | 高 | 切换到任意用户 |
| CAP_SETGID | 高 | 切换到任意组 |
| CAP_NET_RAW | 中高 | 原始网络访问、嗅探 |
| CAP_NET_ADMIN | 中高 | 网络配置修改 |
| CAP_BPF | 中高 | 加载 BPF 程序 |
| CAP_PERFMON | 中 | 性能监控，可能泄露信息 |

**利用示例**（CAP_SYS_ADMIN）：
```bash
# 挂载 host 文件系统
mount -t tmpfs none /mnt
mount --bind / /mnt
chroot /mnt
```

**MITRE ATT&CK ID**：T1548

### 2.4 内核漏洞利用

**原理**：
利用 Linux 内核中的漏洞（如缓冲区溢出、竞态条件、类型混淆等）直接获取内核态权限。

**著名漏洞**：

| 漏洞 | CVE | 影响版本 | 类型 |
|------|-----|---------|------|
| Dirty COW | CVE-2016-5195 | 2.x - 4.8.x | 竞态条件 |
| Dirty Pipe | CVE-2022-0847 | 5.8 - 5.16.10 | 管道缓冲区覆写 |
| OverlayFS | CVE-2023-0386 | 5.11 - 6.2 | OverlayFS 权限绕过 |
| nftables | CVE-2023-32233 | 5.x - 6.x | UAF |
| io_uring | CVE-2022-29582 | 5.10 - 5.17 | UAF |

**利用特点**：
- 通常需要针对特定内核版本
- 利用成功后直接获得 root 权限
- 可能导致系统不稳定

**MITRE ATT&CK ID**：T1068

### 2.5 容器逃逸

**原理**：
容器共享宿主机内核，配置不当或内核漏洞可导致逃逸到宿主机。

**主要逃逸技术**：

1. **Cgroup Release Agent**：
   - 修改 `release_agent` 文件
   - 触发 cgroup 释放时在宿主机执行命令

2. **特权容器逃逸**：
   - `--privileged` 容器拥有所有 Capabilities
   - 可挂载宿主机设备和文件系统

3. **挂载逃逸**：
   - 挂载 `/` 或 `/etc` 目录
   - 修改宿主机敏感文件

4. **Docker Socket 暴露**：
   - 挂载 `/var/run/docker.sock`
   - 创建特权容器逃逸

5. **内核漏洞**：
   - 利用内核漏洞直接逃逸

**Cgroup Release Agent 利用示例**：
```bash
# 挂载 cgroup
mount -t cgroup -o memory cgroup /tmp/cgroup
mkdir /tmp/cgroup/x
echo 1 > /tmp/cgroup/x/notify_on_release

# 获取宿主机路径
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > /tmp/cgroup/release_agent

# 准备逃逸命令
echo '#!/bin/sh' > /cmd
echo "cat /etc/shadow > $host_path/output" >> /cmd
chmod a+x /cmd

# 触发逃逸
sh -c "echo \$\$ > /tmp/cgroup/x/cgroup.procs"
```

**MITRE ATT&CK ID**：T1611

### 2.6 进程注入

**原理**：
向其他进程注入代码，以该进程的权限执行恶意操作。

**技术分类**：

1. **Ptrace 注入**：
   - 使用 ptrace 系统调用附加到目标进程
   - 修改内存或寄存器注入代码
   - 需要 CAP_SYS_PTRACE 或同一用户

2. **/proc/[pid]/mem 注入**：
   - 直接写入进程内存空间
   - 需要相同用户或 root 权限

3. **LD_PRELOAD 注入**：
   - 在进程启动时加载恶意共享库
   - 适用于新启动的进程

4. **process_vm_writev 注入**：
   - 使用 process_vm_writev 系统调用
   - 直接跨进程写入内存

**MITRE ATT&CK ID**：T1055

### 2.7 内核模块加载

**原理**：
加载恶意内核模块（LKM）直接在内核态执行代码，获得最高权限。

**攻击方式**：
1. **直接加载恶意模块**：使用 insmod/modprobe 加载
2. **替换合法模块**：替换系统使用的内核模块
3. **Rootkit 植入**：隐藏进程、文件、网络连接

**检测难点**：
- 内核态代码难以监控
- 可修改系统调用表
- 可隐藏自身

**MITRE ATT&CK ID**：T1547.006

### 2.8 LD_PRELOAD/动态链接器劫持

**原理**：
通过设置 LD_PRELOAD 环境变量或修改 /etc/ld.so.preload，在程序运行时加载恶意共享库。

**攻击向量**：
1. **LD_PRELOAD 环境变量**：影响新启动的进程
2. **/etc/ld.so.preload 文件**：全局预加载
3. **/etc/ld.so.conf 修改**：添加恶意库搜索路径
4. **RPATH 利用**：利用二进制文件中的 RPATH 设置

**防护措施**：
- SUID 程序默认忽略 LD_PRELOAD
- 使用静态链接
- 设置 RELRO 保护

**MITRE ATT&CK ID**：T1574.006

### 2.9 计划任务滥用

**原理**：
利用 cron、systemd timer、at 等计划任务机制执行特权命令。

**攻击向量**：
1. **可写的 cron 脚本**：修改 root 的 cron 任务执行的脚本
2. **cron.d 目录写入**：添加恶意 cron 任务
3. **systemd timer 滥用**：创建或修改 systemd 定时器
4. **通配符注入**：利用 cron 命令中的通配符

**常见目标**：
```
/etc/crontab
/etc/cron.d/
/var/spool/cron/
/etc/cron.{hourly,daily,weekly,monthly}/
```

**MITRE ATT&CK ID**：T1053

### 2.10 文件权限配置错误

**原理**：
利用敏感文件或目录的不当权限进行提权。

**常见目标**：
| 文件/目录 | 利用方式 |
|-----------|----------|
| /etc/passwd | 添加 root 用户 |
| /etc/shadow | 修改 root 密码哈希 |
| /etc/sudoers | 添加 sudo 权限 |
| /root/.ssh/authorized_keys | 添加 SSH 公钥 |
| /etc/cron.d/ | 添加 cron 任务 |
| SUID 程序的库路径 | 库劫持 |

**MITRE ATT&CK ID**：T1222

---

## 3. 本地提权检测方法

### 3.1 检测层次架构

本地提权检测可在多个层次实施：

```
┌─────────────────────────────────────────┐
│           应用层检测                      │
│   (日志分析、行为基线、异常检测)           │
├─────────────────────────────────────────┤
│           用户空间检测                    │
│   (进程监控、文件完整性、audit)           │
├─────────────────────────────────────────┤
│           系统调用层检测                  │
│   (seccomp、LSM、eBPF)                   │
├─────────────────────────────────────────┤
│           内核层检测                      │
│   (内核函数 hook、数据结构监控)            │
└─────────────────────────────────────────┘
```

### 3.2 系统调用监控

**关键系统调用**：

| 系统调用 | 监控目的 |
|----------|----------|
| setuid/setgid | UID/GID 变更 |
| setresuid/setresgid | 完整的 UID/GID 设置 |
| setfsuid/setfsgid | 文件系统 UID/GID |
| execve/execveat | 程序执行 |
| ptrace | 进程调试 |
| init_module/finit_module | 内核模块加载 |
| mount/umount | 文件系统挂载 |
| capset | Capability 设置 |

**实现方式**：
1. **Audit 框架**：auditd 规则
2. **eBPF**：tracepoint/kprobe hook
3. **Seccomp**：系统调用过滤
4. **LSM**：强制访问控制

**Auditd 规则示例**：
```bash
# 监控 setuid 调用
-a always,exit -F arch=b64 -S setuid -S setgid -S setreuid -S setregid -k privilege_escalation

# 监控 sudo 配置修改
-w /etc/sudoers -p wa -k sudoers_modification
-w /etc/sudoers.d/ -p wa -k sudoers_modification
```

### 3.3 内核函数监控

**关键内核函数**：

| 函数 | 作用 | 检测价值 |
|------|------|----------|
| commit_creds | 应用凭证变更 | 检测任何凭证修改 |
| cap_capable | Capability 检查 | 检测高危 cap 请求 |
| prepare_creds | 准备新凭证 | 检测凭证创建 |
| override_creds | 临时凭证覆盖 | 检测权限临时提升 |
| security_* | LSM 钩子 | 安全策略检查点 |

**commit_creds 检测逻辑**：
```
1. 获取旧凭证 (old_cred)
2. 获取新凭证 (new_cred)
3. 比较关键字段:
   - UID/GID 变化
   - EUID/EGID 变化
   - Capabilities 变化
4. 如有异常变化，触发告警
```

### 3.4 文件完整性监控

**关键文件**：
```
/etc/passwd
/etc/shadow
/etc/sudoers
/etc/sudoers.d/*
/etc/crontab
/etc/cron.d/*
/etc/ld.so.preload
/etc/ld.so.conf
/etc/ld.so.conf.d/*
/root/.ssh/authorized_keys
```

**监控方式**：
1. **Inotify**：实时文件变更通知
2. **定期哈希校验**：AIDE、OSSEC
3. **LSM Hook**：security_file_open 等

### 3.5 行为分析检测

**异常行为模式**：
1. **凭证异常变更**：非 sudo/su 的 UID 变化
2. **异常进程树**：Web 服务器进程 spawn shell
3. **敏感文件访问**：非特权进程读取 /etc/shadow
4. **异常网络连接**：反向 shell 连接
5. **时间异常**：非工作时间的特权操作

**检测规则示例**：
```yaml
# 检测凭证变更（非 sudo/su）
rule: credential_change_suspicious
condition:
  - event: commit_creds
  - old_uid != new_uid
  - process.name not in [sudo, su, login, sshd]
severity: high
```

### 3.6 LSM（Linux Security Modules）

**主要 LSM 框架**：
- SELinux
- AppArmor
- SMACK
- TOMOYO

**LSM 钩子函数**（安全相关）：
| 钩子 | 用途 |
|------|------|
| security_task_setuid | UID 设置检查 |
| security_capable | Capability 检查 |
| security_file_open | 文件打开检查 |
| security_sb_mount | 挂载检查 |
| security_bprm_check | 程序执行检查 |

---

## 4. Tracee检测实现分析

### 4.1 Tracee 架构概述

Tracee 是 Aqua Security 开发的基于 eBPF 的运行时安全和取证工具，其架构如下：

```
┌──────────────────────────────────────────────────────┐
│                   用户空间                            │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  │
│  │  事件处理器  │  │  签名引擎   │  │   输出模块   │  │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  │
│         │                │                │          │
│  ┌──────┴────────────────┴────────────────┴──────┐  │
│  │              Perf Buffer / Ring Buffer         │  │
│  └──────────────────────┬───────────────────────┘  │
├─────────────────────────┼────────────────────────────┤
│                   内核空间                            │
│  ┌──────────────────────┴───────────────────────┐  │
│  │                 eBPF 程序                      │  │
│  │  ┌─────────┐ ┌─────────┐ ┌─────────────────┐  │  │
│  │  │Kprobes  │ │Tracepoint│ │ LSM Programs    │  │  │
│  │  └─────────┘ └─────────┘ └─────────────────┘  │  │
│  └──────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────┘
```

**核心组件**：
1. **eBPF 程序**：运行在内核态，捕获系统事件
2. **事件处理器**：解析和处理内核事件
3. **签名引擎**：基于规则的威胁检测
4. **输出模块**：多种输出格式支持

### 4.2 eBPF 凭证变更检测

**commit_creds 追踪实现**（`pkg/ebpf/c/tracee.bpf.c:2397-2478`）：

```c
SEC("kprobe/commit_creds")
int BPF_KPROBE(trace_commit_creds)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx, COMMIT_CREDS))
        return 0;

    if (!evaluate_scope_filters(&p))
        return 0;

    // 获取新旧凭证
    struct cred *new_cred = (struct cred *) PT_REGS_PARM1(ctx);
    struct cred *old_cred = (struct cred *) get_task_real_cred(p.event->task);

    slim_cred_t old_slim = {0};
    slim_cred_t new_slim = {0};

    // 读取旧凭证
    old_slim.uid = BPF_CORE_READ(old_cred, uid.val);
    old_slim.gid = BPF_CORE_READ(old_cred, gid.val);
    old_slim.euid = BPF_CORE_READ(old_cred, euid.val);
    old_slim.egid = BPF_CORE_READ(old_cred, egid.val);
    old_slim.cap_inheritable = credcap_to_slimcap(&old_cred->cap_inheritable);
    old_slim.cap_permitted = credcap_to_slimcap(&old_cred->cap_permitted);
    old_slim.cap_effective = credcap_to_slimcap(&old_cred->cap_effective);
    // ... 其他字段 ...

    // 读取新凭证
    new_slim.uid = BPF_CORE_READ(new_cred, uid.val);
    new_slim.gid = BPF_CORE_READ(new_cred, gid.val);
    // ... 其他字段 ...

    // 保存新旧凭证到事件缓冲区
    save_to_submit_buf(&p.event->args_buf, (void *) &old_slim, sizeof(slim_cred_t), 0);
    save_to_submit_buf(&p.event->args_buf, (void *) &new_slim, sizeof(slim_cred_t), 1);

    // 检测凭证变化
    if (
        (old_slim.uid != new_slim.uid)                          ||
        (old_slim.gid != new_slim.gid)                          ||
        (old_slim.euid != new_slim.euid)                        ||
        (old_slim.egid != new_slim.egid)                        ||
        (old_slim.cap_inheritable != new_slim.cap_inheritable)  ||
        (old_slim.cap_permitted != new_slim.cap_permitted)      ||
        (old_slim.cap_effective != new_slim.cap_effective)      ||
        // ... 其他比较 ...
    ) {
        events_perf_submit(&p, 0);  // 提交事件
    }

    return 0;
}
```

**检测逻辑分析**：
1. 获取 commit_creds 的参数（新凭证指针）
2. 获取当前任务的旧凭证
3. 读取并比较所有凭证字段
4. 只有当凭证发生变化时才提交事件
5. 用户空间进一步分析变化是否可疑

### 4.3 eBPF Capability 检测

**cap_capable 追踪实现**（`pkg/ebpf/c/tracee.bpf.c:2530-2549`）：

```c
SEC("kprobe/cap_capable")
int BPF_KPROBE(trace_cap_capable)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx, CAP_CAPABLE))
        return 0;

    if (!evaluate_scope_filters(&p))
        return 0;

    int cap = PT_REGS_PARM3(ctx);      // 请求的 capability
    int cap_opt = PT_REGS_PARM4(ctx);  // 选项标志

    // 过滤探测性检查（减少噪音）
    if (cap_opt & CAP_OPT_NOAUDIT)
        return 0;

    save_to_submit_buf(&p.event->args_buf, (void *) &cap, sizeof(int), 0);

    return events_perf_submit(&p, 0);
}
```

**检测逻辑分析**：
1. hook `cap_capable` 内核函数
2. 获取请求的 capability 编号
3. 过滤 `CAP_OPT_NOAUDIT` 标志（探测性检查）
4. 提交事件供用户空间分析

**CAP_OPT_NOAUDIT 说明**：
- 内核在某些情况下会探测性地检查 capability
- 这些检查不应触发审计日志
- 过滤这些检查可减少误报

### 4.4 SlimCred 数据结构

**定义**（`pkg/ebpf/c/types.h:538-554`）：

```c
typedef struct slim_cred {
    uid_t uid;           // 真实 UID
    gid_t gid;           // 真实 GID
    uid_t suid;          // 保存的 UID
    gid_t sgid;          // 保存的 GID
    uid_t euid;          // 有效 UID
    gid_t egid;          // 有效 GID
    uid_t fsuid;         // 文件系统 UID
    gid_t fsgid;         // 文件系统 GID
    u32 user_ns;         // 用户命名空间
    u32 securebits;      // SUID-less 安全管理
    u64 cap_inheritable; // 可继承的 capabilities
    u64 cap_permitted;   // 允许的 capabilities
    u64 cap_effective;   // 有效的 capabilities
    u64 cap_bset;        // capability 边界集
    u64 cap_ambient;     // 环境 capability 集
} slim_cred_t;
```

**设计考量**：
- 精简版的内核 `struct cred`
- 只包含安全相关字段
- 适合在 eBPF 和用户空间之间传递
- 固定大小便于处理

### 4.5 签名引擎架构

**签名接口**（`types/detect/detect.go`）：

```go
type Signature interface {
    // 获取签名元数据
    GetMetadata() (SignatureMetadata, error)

    // 获取关注的事件
    GetSelectedEvents() ([]SignatureEventSelector, error)

    // 初始化
    Init(ctx SignatureContext) error

    // 事件处理
    OnEvent(event protocol.Event) error

    // 信号处理
    OnSignal(signal Signal) error

    // 清理
    Close()
}

type SignatureMetadata struct {
    ID          string                 // 签名 ID
    Version     string                 // 版本
    Name        string                 // 名称
    EventName   string                 // 事件名
    Description string                 // 描述
    Properties  map[string]interface{} // 属性（严重性、ATT&CK 等）
}
```

### 4.6 提权相关签名规则

**Sudoers 修改检测**（`signatures/golang/sudoers_modification.go`）：

```go
type SudoersModification struct {
    cb           detect.SignatureHandler
    sudoersFiles []string
    sudoersDirs  []string
}

func (sig *SudoersModification) Init(ctx detect.SignatureContext) error {
    sig.cb = ctx.Callback
    sig.sudoersFiles = []string{"/etc/sudoers", "/private/etc/sudoers"}
    sig.sudoersDirs = []string{"/etc/sudoers.d/", "/private/etc/sudoers.d/"}
    return nil
}

func (sig *SudoersModification) GetMetadata() (detect.SignatureMetadata, error) {
    return detect.SignatureMetadata{
        ID:          "TRC-1028",
        Version:     "1",
        Name:        "Sudoers file modification detected",
        EventName:   "sudoers_modification",
        Description: "The sudoers file was modified...",
        Properties: map[string]interface{}{
            "Severity":    2,
            "Category":    "privilege-escalation",
            "Technique":   "Sudo and Sudo Caching",
            "external_id": "T1548.003",
        },
    }, nil
}

func (sig *SudoersModification) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
    return []detect.SignatureEventSelector{
        {Source: "tracee", Name: "security_file_open", Origin: "*"},
        {Source: "tracee", Name: "security_inode_rename", Origin: "*"},
    }, nil
}

func (sig *SudoersModification) OnEvent(event protocol.Event) error {
    eventObj := event.Payload.(trace.Event)

    switch eventObj.EventName {
    case "security_file_open":
        flags, _ := eventObj.GetIntArgumentByName("flags")
        if parsers.IsFileWrite(flags) {
            pathname, _ := eventObj.GetStringArgumentByName("pathname")
            // 检查是否为 sudoers 文件
            for _, sudoersFile := range sig.sudoersFiles {
                if pathname == sudoersFile {
                    return sig.match(event)
                }
            }
        }
    case "security_inode_rename":
        // 检查重命名到 sudoers 目录
        // ...
    }
    return nil
}
```

**完整签名规则列表**（提权相关）：

| 签名 ID | 文件 | 检测目标 | MITRE ATT&CK |
|---------|------|----------|--------------|
| TRC-1028 | sudoers_modification.go | Sudoers 文件修改 | T1548.003 |
| TRC-1010 | cgroup_release_agent_modification.go | Cgroup release agent | T1611 |
| TRC-1011 | cgroup_notify_on_release_modification.go | notify_on_release 修改 | T1611 |
| TRC-1017 | kernel_module_loading.go | 内核模块加载 | T1547.006 |
| TRC-103 | ptrace_code_injection.go | Ptrace 代码注入 | T1055.008 |
| TRC-1019 | proc_mem_code_injection.go | /proc/mem 注入 | T1055.009 |
| TRC-107 | ld_preload.go | LD_PRELOAD 劫持 | T1574.006 |
| TRC-1018 | proc_kcore_read.go | /proc/kcore 读取 | T1003 |
| TRC-1023 | core_pattern_modification.go | core_pattern 修改 | T1546 |
| TRC-1022 | system_request_key_config_modification.go | request_key 修改 | T1547 |
| TRC-105 | fileless_execution.go | 无文件执行 | T1620 |
| TRC-1014 | default_loader_modification.go | 默认加载器修改 | T1574 |

### 4.7 事件处理流程

```
1. 内核事件触发
   └── eBPF 程序捕获
       └── 数据写入 Perf Buffer

2. 用户空间读取
   └── 事件解析器
       └── 事件对象创建

3. 签名引擎处理
   └── 遍历所有签名
       └── 匹配事件类型
           └── 执行检测逻辑

4. 告警输出
   └── Finding 对象
       └── 输出模块
           └── stdout/webhook/syslog
```

---

## 5. 高危 Capabilities 详解

### 5.1 CAP_SYS_ADMIN

**定义**：几乎等同于 root 的超级 capability

**允许的操作**：
- 挂载/卸载文件系统
- 修改内核参数（sysctl）
- 加载 BPF 程序（旧内核）
- 设置进程记账
- 配置磁盘配额
- 执行 ioctl 操作
- 使用 perf_event_open
- 等等...

**风险评估**：极高

**利用方式**：
```bash
# 挂载 overlay 获取宿主机访问
mount -t overlay overlay -o lowerdir=/,upperdir=/tmp/upper,workdir=/tmp/work /mnt
```

### 5.2 CAP_SYS_MODULE

**定义**：允许加载和卸载内核模块

**允许的操作**：
- init_module() / finit_module()
- delete_module()

**风险评估**：极高

**利用方式**：加载恶意内核模块获得 ring0 权限

### 5.3 CAP_SYS_PTRACE

**定义**：允许跟踪任意进程

**允许的操作**：
- ptrace(PTRACE_ATTACH)
- 读写任意进程内存
- 修改寄存器

**风险评估**：高

**利用方式**：
- 注入 shellcode 到特权进程
- 提取进程内存中的敏感数据
- 调试器攻击

### 5.4 CAP_NET_RAW

**定义**：允许使用原始套接字

**允许的操作**：
- 创建 RAW socket
- 创建 PACKET socket
- 绑定到任意地址

**风险评估**：中高

**利用方式**：
- 网络嗅探
- ARP 欺骗
- 原始数据包注入

### 5.5 CAP_BPF

**定义**：允许加载 BPF 程序（Linux 5.8+）

**允许的操作**：
- bpf() 系统调用
- 加载 eBPF 程序

**风险评估**：中高

**利用方式**：
- 加载恶意 eBPF 程序
- 内核内存读取
- 系统调用劫持

### 5.6 CAP_SETUID / CAP_SETGID

**定义**：允许设置 UID/GID

**允许的操作**：
- setuid() / setgid()
- setresuid() / setresgid()
- setfsuid() / setfsgid()

**风险评估**：高

**利用方式**：
```c
setuid(0);  // 直接切换到 root
execl("/bin/sh", "sh", NULL);
```

### 5.7 Capability 检测策略

```yaml
# Tracee 策略：监控高危 Capability 请求
apiVersion: tracee.aquasecurity.github.io/v1beta1
kind: Policy
metadata:
  name: dangerous-capabilities
spec:
  rules:
    - event: cap_capable
      filters:
        - args.cap=CAP_SYS_ADMIN
        - args.cap=CAP_SYS_MODULE
        - args.cap=CAP_SYS_PTRACE
        - args.cap=CAP_NET_RAW
        - args.cap=CAP_BPF
```

---

## 6. 检测策略与配置

### 6.1 综合提权检测策略

```yaml
apiVersion: tracee.aquasecurity.github.io/v1beta1
kind: Policy
metadata:
  name: privilege-escalation-detection
  annotations:
    description: 综合本地提权检测策略
spec:
  scope:
    - global

  rules:
    # 1. 凭证变更检测
    - event: commit_creds

    # 2. 高危 Capability 检测
    - event: cap_capable
      filters:
        - args.cap=CAP_SYS_ADMIN
        - args.cap=CAP_SYS_MODULE
        - args.cap=CAP_SYS_PTRACE
        - args.cap=CAP_SETUID

    # 3. 敏感文件访问
    - event: security_file_open
      filters:
        - args.pathname=/etc/sudoers
        - args.pathname=/etc/shadow
        - args.pathname=/etc/passwd

    # 4. 进程执行检测
    - event: sched_process_exec
      filters:
        - args.pathname=/usr/bin/sudo
        - args.pathname=/bin/su

    # 5. 内核模块加载
    - event: security_kernel_module_request
    - event: init_module
    - event: finit_module

    # 6. Ptrace 检测
    - event: ptrace
      filters:
        - args.request=PTRACE_ATTACH
        - args.request=PTRACE_POKETEXT
```

### 6.2 容器环境检测策略

```yaml
apiVersion: tracee.aquasecurity.github.io/v1beta1
kind: Policy
metadata:
  name: container-privilege-escalation
spec:
  scope:
    - container=true

  rules:
    # 容器逃逸检测
    - event: security_file_open
      filters:
        - args.pathname=/sys/fs/cgroup/**/release_agent
        - args.pathname=/sys/fs/cgroup/**/notify_on_release

    # 特权操作检测
    - event: cap_capable
      filters:
        - args.cap=CAP_SYS_ADMIN
        - args.cap=CAP_SYS_MODULE

    # 挂载检测
    - event: security_sb_mount
```

### 6.3 告警响应配置

```yaml
# 输出到 Webhook
apiVersion: tracee.aquasecurity.github.io/v1beta1
kind: TraceeConfig
metadata:
  name: alert-config
spec:
  output:
    - webhook:
        url: https://security-alerts.company.com/tracee
        headers:
          Authorization: Bearer <token>

  # 只输出高严重性告警
  filter:
    severity:
      min: 2  # medium 及以上
```

---

## 7. 总结与建议

### 7.1 攻击手法总结

本地提权攻击主要利用以下弱点：

1. **配置错误**：SUID、Sudo、文件权限
2. **软件漏洞**：内核、SUID 程序、特权服务
3. **设计缺陷**：Capabilities 细粒度不足、容器隔离不完善
4. **运维疏忽**：未及时修补、默认配置

### 7.2 检测能力评估

| 检测方法 | 覆盖范围 | 实时性 | 准确性 | 性能影响 |
|----------|----------|--------|--------|----------|
| Auditd | �� | 高 | 中 | 低 |
| eBPF (Tracee) | 高 | 高 | 高 | 中 |
| LSM | 中高 | 高 | 高 | 低 |
| 文件完整性 | 低 | 中 | 高 | 低 |
| 日志分析 | 中 | 低 | 中 | 极低 |

### 7.3 防护建议

**纵深防御策略**：

1. **最小权限原则**
   - 移除不必要的 SUID 位
   - 限制 Sudo 权限
   - 使用细粒度 Capabilities

2. **配置加固**
   - 定期审计 sudoers 配置
   - 检查文件权限
   - 禁用不必要的内核模块

3. **运行时检测**
   - 部署 eBPF 安全工具
   - 配置实时告警
   - 建立行为基线

4. **容器安全**
   - 避免使用特权容器
   - 限制 Capabilities
   - 使用安全的运行时

5. **补丁管理**
   - 及时更新内核
   - 跟踪安全公告
   - 自动化补丁流程

### 7.4 Tracee 部署建议

1. **基础部署**：监控关键提权事件
2. **签名启用**：启用所有提权相关签名
3. **策略调优**：根据环境调整过滤规则
4. **告警集成**：对接 SIEM/SOAR 系统
5. **持续优化**：根据误报调整规则

---

## 8. 参考资料

### 8.1 官方文档
- [Tracee Documentation](https://aquasecurity.github.io/tracee/)
- [Linux Capabilities Manual](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [MITRE ATT&CK](https://attack.mitre.org/tactics/TA0004/)

### 8.2 关键代码文件
| 文件 | 说明 |
|------|------|
| `pkg/ebpf/c/tracee.bpf.c` | 主 eBPF 程序 |
| `pkg/ebpf/c/types.h` | 数据结构定义 |
| `pkg/ebpf/c/common/capabilities.h` | Capability 处理 |
| `signatures/golang/*.go` | 签名规则实现 |
| `pkg/signatures/engine/engine.go` | 签名引擎 |

### 8.3 扩展阅读
- [GTFOBins](https://gtfobins.github.io/) - Unix 二进制利用
- [HackTricks - Linux Privilege Escalation](https://book.hacktricks.xyz/linux-hardening/privilege-escalation)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md)

---

*文档结束*
