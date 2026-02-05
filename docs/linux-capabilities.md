# Linux Capabilities 详解

---

## 1. 什么是 Capabilities

传统 Unix 权限模型很简单粗暴：要么你是 root（UID=0）拥有一切权限，要么你是普通用户受各种限制。这带来一个问题——很多程序只需要一点点特权（比如 ping 只需要发 ICMP 包），却不得不以 root 身份运行。

Linux 2.2 引入了 Capabilities 机制，把 root 的"超级权限"拆分成 40 多个独立的小权限。程序可以只获得需要的那几个，而不是全部。

```
传统模型：
  普通用户 ──────────────────────────── root（全部权限）
                    巨大鸿沟

Capabilities 模型：
  普通用户 ─┬─ +CAP_NET_RAW ────────── 可以发原始网络包
            ├─ +CAP_NET_BIND_SERVICE ─ 可以绑定 <1024 端口
            ├─ +CAP_SYS_PTRACE ─────── 可以调试其他进程
            └─ +CAP_SYS_ADMIN ────────  几乎等于 root
```

## 2. 进程的 Capability 集合

每个进程有 5 个 capability 集合：

| 集合 | 说明 |
|------|------|
| **Permitted (P)** | 进程"允许拥有"的上限，可以从这里激活到 Effective |
| **Effective (E)** | 当前实际生效的，内核检查权限看的就是它 |
| **Inheritable (I)** | execve 时可以传递给新程序的 |
| **Bounding (B)** | 硬性上限，进程永远无法获得超出它的 capability |
| **Ambient (A)** | Linux 4.3 新增，普通程序也能继承的 capability |

常见操作：
```bash
# 查看当前 shell 的 capabilities
cat /proc/$$/status | grep Cap

# 解码 capability 位图
capsh --decode=0000003fffffffff

# 查看进程的 capabilities
getpcaps <pid>
```

## 3. 文件的 Capability

可执行文件也可以设置 capabilities，执行时赋予进程：

```bash
# 查看文件的 capabilities
getcap /usr/bin/ping

# 设置文件 capabilities
sudo setcap cap_net_raw+ep /usr/bin/ping
#                      ││
#                      │└─ p = permitted
#                      └── e = effective

# 移除文件 capabilities
sudo setcap -r /usr/bin/ping
```

`+ep` 的含义：
- `e` (effective): 执行时自动激活
- `p` (permitted): 加入进程的 permitted 集合
- `i` (inheritable): 可继承给子进程

## 4. Capability 继承规则

执行新程序时（execve），capabilities 按以下规则计算：

```
P'(permitted)   = (P(inheritable) & F(inheritable)) |
                  (F(permitted) & B(bounding)) | P'(ambient)
P'(effective)   = F(effective) ? P'(permitted) : P'(ambient)
P'(inheritable) = P(inheritable)
P'(ambient)     = (file has caps) ? 0 : P(ambient)
```

简单理解：
- 普通程序（没设 file cap）：只能继承 ambient capabilities
- 有 file cap 的程序：按文件设置获得 capabilities，ambient 被清空
- bounding set 是硬上限，永远不能超过

## 5. 常用 Capabilities 列表

### 5.1 文件/权限相关

| Capability | 作用 |
|------------|------|
| CAP_DAC_OVERRIDE | 绕过文件读/写/执行权限检查 |
| CAP_DAC_READ_SEARCH | 绕过文件读权限和目录搜索权限 |
| CAP_FOWNER | 绕过"必须是文件所有者"的检查 |
| CAP_CHOWN | 允许修改文件所有者 |

### 5.2 进程/用户相关

| Capability | 作用 |
|------------|------|
| CAP_SETUID | 允许 setuid() 切换用户 |
| CAP_SETGID | 允许 setgid() 切换组 |
| CAP_KILL | 允许向任意进程发信号 |
| CAP_SYS_PTRACE | 允许 ptrace 任意进程 |
| CAP_SYS_NICE | 允许修改进程优先级 |

### 5.3 网络相关

| Capability | 作用 |
|------------|------|
| CAP_NET_RAW | 使用原始套接字（ping、抓包） |
| CAP_NET_BIND_SERVICE | 绑定 <1024 的端口 |
| CAP_NET_ADMIN | 网络管理（配置接口、路由、防火墙） |

### 5.4 系统管理相关

| Capability | 作用 |
|------------|------|
| CAP_SYS_ADMIN | "万能钥匙"，包含大量杂项特权 |
| CAP_SYS_MODULE | 加载/卸载内核模块 |
| CAP_SYS_BOOT | 重启系统 |
| CAP_SYS_TIME | 修改系统时间 |
| CAP_SYS_RESOURCE | 覆盖资源限制 |
| CAP_MKNOD | 创建设备文件 |

### 5.5 BPF/性能相关

| Capability | 作用 |
|------------|------|
| CAP_BPF | 加载 BPF 程序（Linux 5.8+） |
| CAP_PERFMON | 使用 perf_event（Linux 5.8+） |

---

## 6. 高危 Capabilities 与提权风险

某些 capabilities 权限过大，拿到就几乎等于 root。

### 6.1 CAP_SYS_ADMIN（极高风险）

这是个"垃圾桶" capability，塞了太多杂项权限：
- 挂载/卸载文件系统
- 修改内核参数（sysctl）
- 加载 BPF 程序（旧内核）
- 配置磁盘配额
- 执行很多 ioctl 操作
- ...

提权利用：
```bash
# 容器内有 CAP_SYS_ADMIN 时，可以挂载宿主机文件系统
mount -t overlay overlay -o lowerdir=/,upperdir=/tmp/u,workdir=/tmp/w /mnt
# 或者
mount --bind /host_path /mnt
chroot /mnt
```

### 6.2 CAP_SYS_MODULE（极高风险）

允许加载内核模块 = 可以在内核态执行任意代码。

```c
// 恶意内核模块示例
static int __init evil_init(void) {
    struct cred *cred = prepare_kernel_cred(NULL);
    commit_creds(cred);  // 当前进程变 root
    return 0;
}
```

### 6.3 CAP_SYS_PTRACE（高风险）

可以调试任意进程，意味着：
- 读取任意进程内存（提取密码、密钥）
- 向特权进程注入代码
- 劫持进程执行流

```bash
# 注入 shellcode 到 root 进程
gdb -p <root_pid>
(gdb) call system("/bin/bash")
```

### 6.4 CAP_SETUID / CAP_SETGID（高风险）

直接切换用户身份：
```c
setuid(0);
execl("/bin/sh", "sh", NULL);
// 现在是 root shell
```

### 6.5 CAP_DAC_OVERRIDE（高风险）

绕过所有文件权限检查，可以：
- 读取 /etc/shadow
- 修改 /etc/passwd 添加 root 用户
- 写入 /root/.ssh/authorized_keys

### 6.6 CAP_NET_RAW（中高风险）

创建原始套接字：
- 网络嗅探，捕获明文密码
- ARP 欺骗，中间人攻击
- 构造任意网络包

### 6.7 CAP_BPF（中高风险）

加载 eBPF 程序：
- 在内核态执行代码
- 读取内核内存
- 劫持系统调用
- 绕过安全监控

---

## 7. 如何检查系统中的 Capabilities

```bash
# 查找设置了 capabilities 的文件
getcap -r / 2>/dev/null

# 查看某个进程的 capabilities
cat /proc/<pid>/status | grep Cap
# 或
getpcaps <pid>

# 查看当前用户的 capability bounding set
cat /proc/self/status | grep CapBnd

# 人类可读格式解码
capsh --decode=<hex_value>
```

---

## 8. 容器中的 Capabilities

Docker/Kubernetes 默认会 drop 大部分 capabilities，只保留必需的。

```bash
# 查看容器默认 capabilities
docker run --rm alpine cat /proc/1/status | grep Cap

# 添加 capability 运行容器（危险！）
docker run --cap-add SYS_ADMIN ...
docker run --cap-add ALL ...  # 非常危险

# 移除特定 capability
docker run --cap-drop NET_RAW ...
```

Kubernetes Pod 配置：
```yaml
securityContext:
  capabilities:
    drop:
      - ALL
    add:
      - NET_BIND_SERVICE
```

**安全建议**：容器应该 drop ALL，只 add 真正需要的。

---

## 9. 参考资料

- [man 7 capabilities](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [Linux Capabilities 内核文档](https://www.kernel.org/doc/html/latest/userspace-api/capabilities.html)
- [HackTricks - Linux Capabilities](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/linux-capabilities)
