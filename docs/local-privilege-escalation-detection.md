# 基于 eBPF 的本地提权检测

---

## 1. eBPF 检测本地提权的 Hook 点选择

检测本地提权，核心问题是：**在哪里 hook 能捕获到权限变化？**

eBPF 提供了多种 hook 机制，我们来分析各自的优缺点。

### 1.1 可选的 Hook 点

#### 方案一：Tracepoint 系统调用层

Hook 权限相关的系统调用：

```
tracepoint/syscalls/sys_enter_setuid
tracepoint/syscalls/sys_enter_setgid
tracepoint/syscalls/sys_enter_setresuid
tracepoint/syscalls/sys_enter_setresgid
tracepoint/syscalls/sys_enter_setfsuid
tracepoint/syscalls/sys_enter_capset
tracepoint/syscalls/sys_enter_execve
```

**优点**：

- 稳定的 ABI，不随内核版本变化
- 能获取用户空间传入的参数

**缺点**：
- 只能看到"请求"，不知道是否成功
- 需要 hook 多个系统调用才能覆盖所有场景
- 无法捕获内核态的权限变化（如内核漏洞利用）
- SUID 程序执行时的权限变化发生在 execve 内部，难以直接观察

#### 方案二：Kprobe 系统调用入口

```
kprobe/__x64_sys_setuid
kprobe/__x64_sys_setresuid
...
```

**优点**：
- 比 tracepoint 更灵活

**缺点**：
- 同样只是入口，不知道结果
- 符号名可能随内核版本变化

**为什么这两种方案都不够好？**

```
正常提权路径（能监控到）：
  用户程序 → setuid() 系统调用 → 内核处理 → commit_creds

内核漏洞提权路径（监控不到！）：
  用户程序 → 触发漏洞 → 直接在内核态调用 commit_creds
                  ↑
                  绕过了系统调用入口！
```

这就是为什么要选择 hook `commit_creds`——它是"最终关卡"，无论走正门还是翻墙进来，最后都要从这过。

#### 方案三：Kprobe 内核凭证函数

```
kprobe/commit_creds      ← 最终方案
kprobe/prepare_creds
kprobe/override_creds
```

**优点**：
- `commit_creds` 是所有权限变化的必经之路
- 一个 hook 点覆盖所有场景
- 能同时获取新旧凭证进行比较

**缺点**：
- 内核内部函数，可能随版本变化（但 commit_creds 非常稳定）

#### 方案四：LSM（Linux Security Modules）Hook

```
lsm/cred_prepare
lsm/cred_commit
lsm/task_fix_setuid
```

**优点**：
- 专门为安全设计的 hook 点
- 可以阻止操作（不仅是检测）

**缺点**：
- 需要 BPF LSM 支持（Linux 5.7+）
- 部分发行版默认未启用

### 1.2 为什么选择 kprobe/commit_creds

```
                    用户态请求
                        │
        ┌───────────────┼───────────────┐
        │               │               │
        ▼               ▼               ▼
    setuid()       execve()      内核漏洞利用
        │               │               │
        │    ┌──────────┘               │
        │    │  (SUID程序)               │
        ▼    ▼                          ▼
    prepare_creds()  ◄──────────────────┘
        │
        ▼
    [修改 cred 结构]
        │
        ▼
    commit_creds()  ◄─── 这里 hook！
        │
        ▼
    权限变化生效
```

**commit_creds 是权限变化的"咽喉要道"**：

1. **覆盖全面**：无论是 setuid、execve 执行SUID 程序，还是内核漏洞利用，其最终都要调用 commit_creds
2. **时机精准**：在 commit_creds 调用时，新凭证已经准备好，可以同时获取新旧凭证
3. **稳定性好**：commit_creds 从 Linux 2.6.29 引入至今，接口未变
4. **性能优**：一个 hook 点替代多个系统调用 hook

### 1.3 Hook 点对比总结

| Hook 点 | 覆盖场景 | 能否检测内核漏洞提权 | 性能 | 稳定性 |
|---------|----------|---------------------|------|--------|
| tracepoint/syscalls | 部分 | ✗ | 需多个hook | 高 |
| kprobe/__x64_sys_setuid系列函数 | 部分 | ✗ | 需多个hook | 中 |
| **kprobe/commit_creds** | **全部** | **✓** | **单hook** | **高** |
| lsm/cred_commit | 全部 | ✓ | 单hook | 需5.7+ |

---

## 2. commit_creds 检测实现

### 2.1 commit_creds 函数分析

```c
// 内核源码 kernel/cred.c
int commit_creds(struct cred *new)
{
    struct task_struct *task = current;
    const struct cred *old = task->real_cred;

    // ... 安全检查 ...

    // 核心流程:替换凭证
    rcu_assign_pointer(task->real_cred, new);
    rcu_assign_pointer(task->cred, new);

    // ... 清理旧凭证 ...

    return 0;
}
```

关键点：
- 参数 `new` 是即将生效的新凭证
- `current->real_cred` 是当前的旧凭证
- 函数执行后，进程权限就变了

### 2.2 eBPF 检测代码

```c
SEC("kprobe/commit_creds")
int BPF_KPROBE(trace_commit_creds)
{
    // 1. 获取新凭证（函数参数）
    struct cred *new_cred = (struct cred *)PT_REGS_PARM1(ctx);

    // 2. 获取旧凭证（当前进程的 real_cred）
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct cred *old_cred;
    bpf_probe_read_kernel(&old_cred, sizeof(old_cred), &task->real_cred);

    // 3. 读取新旧凭证的关键字段
    uid_t old_uid, new_uid;
    uid_t old_euid, new_euid;

    bpf_probe_read_kernel(&old_uid, sizeof(old_uid), &old_cred->uid.val);
    bpf_probe_read_kernel(&new_uid, sizeof(new_uid), &new_cred->uid.val);
    bpf_probe_read_kernel(&old_euid, sizeof(old_euid), &old_cred->euid.val);
    bpf_probe_read_kernel(&new_euid, sizeof(new_euid), &new_cred->euid.val);

    // 4. 检测权限提升
    // 情况1: UID 变成 0（变成 root）
    // 情况2: EUID 变成 0（有效权限变��� root）
    // 情况3: 从非 0 变成 0

    if ((old_euid != 0 && new_euid == 0) ||
        (old_uid != 0 && new_uid == 0)) {
        // 权限提升！提交事件
    }

    return 0;
}
```

### 2.3 完整的检测数据结构

```c
// 精简的凭证结构，用于在 eBPF 和用户空间之间传递
typedef struct slim_cred {
    uid_t uid;           // 真实 UID
    gid_t gid;           // 真实 GID
    uid_t suid;          // 保存的 UID
    gid_t sgid;          // 保存的 GID
    uid_t euid;          // 有效 UID
    gid_t egid;          // 有效 GID
    uid_t fsuid;         // 文件系统 UID
    gid_t fsgid;         // 文件系统 GID
    u64 cap_inheritable; // 可继承的 capabilities
    u64 cap_permitted;   // 允许的 capabilities
    u64 cap_effective;   // 有效的 capabilities
    u64 cap_bset;        // capability 边界集
    u64 cap_ambient;     // 环境 capabilities
} slim_cred_t;

struct event_t {
    u32 pid;
    u32 tid;
    u32 ppid;
    char comm[16];
    char parent_comm[16];
    slim_cred_t old_cred;
    slim_cred_t new_cred;
};
```

### 2.4 检测逻辑

```
                    commit_creds 被调用
                            │
                            ▼
            ┌───────────────────────────────┐
            │  读取 old_cred 和 new_cred    │
            └───────────────────────────────┘
                            │
                            ▼
            ┌──────────────────────────────┐
            │  比较 UID/GID/Capabilities    │
            └───────────────────────────────┘
                            │
                ┌───────────┴───────────┐
                │                       │
                ▼                       ▼
        凭证无变化               凭证有变化
        （忽略此行为）                      │
                                      ▼
                        ┌─────────────────────────┐
                        │  是否为"权限提升"？      │
                        │  old_euid!=0 && new_euid==0 │
                        │  或 capabilities 增加    │
                        └─────────────────────────┘
                                      │
                        ┌─────────────┴─────────────┐
                        │                           │
                        ▼                           ▼
                正常提权（sudo等）           可疑提权
                （记录但不告警）              （告警！）
```

### 2.5 区分正常提权和可疑提权

关键问题：sudo、su 也会触发 commit_creds，如何区分？

**方法一：检查进程名**

```c
// 白名单进程
const char *whitelist[] = {"sudo", "su", "login", "sshd", "cron"};

// 如果是白名单进程触发的，降低告警级别
if (is_in_whitelist(comm)) {
    event.severity = SEVERITY_INFO;
} else {
    event.severity = SEVERITY_HIGH;
}
```

**方法二：检查进程链**

```c
// 可疑场景：Web 服务器进程的子进程获得 root
// nginx -> php-fpm -> [恶意进程] -> commit_creds(euid=0)

// 检查父进程是否为已知的服务进程
if (parent_comm in ["nginx", "apache", "php-fpm", "node"]) {
    event.severity = SEVERITY_CRITICAL;
}
```

**方法三：检查调用栈**

```c
// 正常的 sudo 调用栈：
// sudo -> setresuid -> commit_creds

// 可疑的内核漏洞利用调用栈：
// [用户程序] -> [漏洞触发] -> commit_creds
// 调用栈中没有 setuid/setresuid 系统调用

// 使用 bpf_get_stack 获取调用栈分析
```

---

## 3. 完整检测架构


```
┌────────────────────────────────────────────────────┐
│                    用户空间                         │
│  ┌──────────────────────────────────────────────┐  │
│  │                 检测引擎                      │  │
│  │  ┌─────────┐  ┌─────────┐  ┌───────────┐    │  │
│  │  │ 事件解析 │  │ 规则匹配 │  │ 告警输出  │    │  │
│  │  └────┬────┘  └────┬────┘  └─────┬─────┘    │  │
│  │       └────────────┴─────────────┘          │  │
│  └────────────────────┬─────────────────────────┘  │
│                       │ perf buffer                │
├───────────────────────┼────────────────────────────┤
│                    内核空间                         │
│  ┌────────────────────┴─────────────────────────┐  │
│  │                 eBPF 程序                     │  │
│  │                                               │  │
│  │  ┌───────────────┐  ┌───────────────────┐    │  │
│  │  │ kprobe/       │  │ kprobe/           │    │  │
│  │  │ commit_creds  │  │ cap_capable       │    │  │
│  │  │ (核心检测点)   │  │ (capability请求)  │    │  │
│  │  └───────────────┘  └───────────────────┘    │  │
│  │                                               │  │
│  │  ┌───────────────┐  ┌───────────────────┐    │  │
│  │  │ kprobe/       │  │ lsm/              │    │  │
│  │  │ do_init_module│  │ file_open         │    │  │
│  │  │ (模块加载)     │  │ (敏感文件访问)    │    │  │
│  │  └───────────────┘  └───────────────────┘    │  │
│  │                                               │  │
│  └───────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────┘
```


---

## 4. 参考资料

- [Linux 内核 cred.c](https://elixir.bootlin.com/linux/latest/source/kernel/cred.c)
- [eBPF CO-RE 参考](https://nakryiko.com/posts/bpf-portability-and-co-re/)
