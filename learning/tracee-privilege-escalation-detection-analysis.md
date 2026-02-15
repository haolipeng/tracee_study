# Tracee 本地提权检测技术分析

本文深入分析 Aquasecurity Tracee 项目如何通过 eBPF 技术检测本地提权行为，结合其实际源码实现，解读其检测思路和架构设计。

---

## 1. Tracee 的检测哲学

### 1.1 多层防御体系

Tracee 采用**分层检测**的设计思路，将本地提权检测分为三个层次：

```
┌─────────────────────────────────────────────────────────────────┐
│                         第三层：行为签名                          │
│                 (检测提权相关的恶意行为模式)                       │
│   sudoers修改、cgroup逃逸、内核模块加载、Docker Socket滥用...     │
├─────────────────────────────────────────────────────────────────┤
│                         第二层：凭证变更                          │
│                 (监控 commit_creds 权限变化)                      │
│             UID/GID/EUID/Capabilities 变更检测                   │
├─────────────────────────────────────────────────────────────────┤
│                         第一层：原始事件                          │
│                   (eBPF 采集的内核事件流)                         │
│      security_file_open, security_sb_mount, cap_capable...      │
└─────────────────────────────────────────────────────────────────┘
```

### 1.2 核心设计原则

1. **Hook 在咽喉要道**：选择 `commit_creds` 作为核心检测点，无论正常提权还是漏洞利用，都必经此处
2. **事件+签名分离**：eBPF 负责采集原始事件，Go 签名负责行为分析
3. **全量凭证对比**：不仅检测 UID 变化，还监控 capabilities、namespace 等完整凭证信息

---

## 2. commit_creds 检测实现

### 2.1 Tracee 的 eBPF 实现

Tracee 在 `pkg/ebpf/c/tracee.bpf.c` 中实现了 commit_creds 的 kprobe：

```c
SEC("kprobe/commit_creds")
int BPF_KPROBE(trace_commit_creds)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx, COMMIT_CREDS))
        return 0;

    if (!evaluate_scope_filters(&p))
        return 0;

    // 1. 获取新旧凭证
    struct cred *new_cred = (struct cred *) PT_REGS_PARM1(ctx);
    struct cred *old_cred = (struct cred *) get_task_real_cred(p.event->task);

    slim_cred_t old_slim = {0};
    slim_cred_t new_slim = {0};

    // 2. 读取 User Namespace 信息
    struct user_namespace *userns_old = BPF_CORE_READ(old_cred, user_ns);
    struct user_namespace *userns_new = BPF_CORE_READ(new_cred, user_ns);

    // 3. 提取旧凭证的关键字段
    old_slim.uid = BPF_CORE_READ(old_cred, uid.val);
    old_slim.gid = BPF_CORE_READ(old_cred, gid.val);
    old_slim.suid = BPF_CORE_READ(old_cred, suid.val);
    old_slim.sgid = BPF_CORE_READ(old_cred, sgid.val);
    old_slim.euid = BPF_CORE_READ(old_cred, euid.val);
    old_slim.egid = BPF_CORE_READ(old_cred, egid.val);
    old_slim.fsuid = BPF_CORE_READ(old_cred, fsuid.val);
    old_slim.fsgid = BPF_CORE_READ(old_cred, fsgid.val);
    old_slim.user_ns = BPF_CORE_READ(userns_old, ns.inum);
    old_slim.securebits = BPF_CORE_READ(old_cred, securebits);

    // 4. 提取 Capabilities (5 种)
    old_slim.cap_inheritable = credcap_to_slimcap(&old_cred->cap_inheritable);
    old_slim.cap_permitted = credcap_to_slimcap(&old_cred->cap_permitted);
    old_slim.cap_effective = credcap_to_slimcap(&old_cred->cap_effective);
    old_slim.cap_bset = credcap_to_slimcap(&old_cred->cap_bset);
    old_slim.cap_ambient = credcap_to_slimcap(&old_cred->cap_ambient);

    // 5. 同样方式提取新凭证...
    // (新凭证提取代码类似，此处省略)

    // 6. 只有当凭证发生变化时才提交事件
    if (
        (old_slim.uid != new_slim.uid)                          ||
        (old_slim.gid != new_slim.gid)                          ||
        (old_slim.suid != new_slim.suid)                        ||
        (old_slim.sgid != new_slim.sgid)                        ||
        (old_slim.euid != new_slim.euid)                        ||
        (old_slim.egid != new_slim.egid)                        ||
        (old_slim.fsuid != new_slim.fsuid)                      ||
        (old_slim.fsgid != new_slim.fsgid)                      ||
        (old_slim.cap_inheritable != new_slim.cap_inheritable)  ||
        (old_slim.cap_permitted != new_slim.cap_permitted)      ||
        (old_slim.cap_effective != new_slim.cap_effective)      ||
        (old_slim.cap_bset != new_slim.cap_bset)                ||
        (old_slim.cap_ambient != new_slim.cap_ambient)
    ) {
        events_perf_submit(&p, 0);
    }

    return 0;
}
```

### 2.2 SlimCred 数据结构

Tracee 定义了精简的凭证结构，用于在内核态和用户态之间高效传递：

```go
// types/trace/trace.go
type SlimCred struct {
    Uid            uint32 /* 真实 UID */
    Gid            uint32 /* 真实 GID */
    Suid           uint32 /* 保存的 UID */
    Sgid           uint32 /* 保存的 GID */
    Euid           uint32 /* 有效 UID */
    Egid           uint32 /* 有效 GID */
    Fsuid          uint32 /* 文件系统 UID */
    Fsgid          uint32 /* 文件系统 GID */
    UserNamespace  uint32 /* 用户命名空间 */
    SecureBits     uint32 /* 安全位设置 */
    CapInheritable uint64 /* 可继承 capabilities */
    CapPermitted   uint64 /* 允许的 capabilities */
    CapEffective   uint64 /* 有效 capabilities */
    CapBounding    uint64 /* capability 边界集 */
    CapAmbient     uint64 /* 环境 capabilities */
}
```

### 2.3 检测逻辑亮点

**亮点一：只上报有变化的事件**

Tracee 不是盲目上报所有 `commit_creds` 调用，而是对比新旧凭证，只有发生实际变化时才提交事件，大大降低了事件量。

**亮点二：全面的凭证字段覆盖**

除了常见的 UID/GID，还监控：
- `fsuid/fsgid`：文件系统操作权限
- `securebits`：安全位（如 SECBIT_NOROOT）
- 五种 capabilities：inheritable、permitted、effective、bounding、ambient

**亮点三：User Namespace 感知**

记录凭证所属的 User Namespace，可区分真正的 root 和容器内的"伪 root"。

---

## 3. cap_capable 检测

### 3.1 Capability 请求监控

Tracee 同时监控 `cap_capable` 函数，捕获进程对特权能力的请求：

```c
SEC("kprobe/cap_capable")
int BPF_KPROBE(trace_cap_capable)
{
    program_data_t p = {};
    if (!init_program_data(&p, ctx, CAP_CAPABLE))
        return 0;

    if (!evaluate_scope_filters(&p))
        return 0;

    int cap = PT_REGS_PARM3(ctx);
    int cap_opt = PT_REGS_PARM4(ctx);

    // 过滤 NOAUDIT 类型的检查（避免噪音）
    if (cap_opt & CAP_OPT_NOAUDIT)
        return 0;

    save_to_submit_buf(&p.event->args_buf, (void *) &cap, sizeof(int), 0);

    return events_perf_submit(&p, 0);
}
```

### 3.2 检测价值

`cap_capable` 事件可以发现：
- 进程尝试获取 `CAP_SYS_ADMIN`（最强权限）
- 进程尝试获取 `CAP_NET_ADMIN`（网络管理）
- 进程尝试获取 `CAP_DAC_OVERRIDE`（绕过文件权限检查）

结合 `commit_creds` 事件，可以完整还原提权过程。

---

## 4. 行为签名检测

Tracee 使用 Go 签名引擎，在原始事件基础上进行高级行为分析。以下是与提权相关的签名：

### 4.1 签名分类

| 签名 ID | 名称 | 检测场景 | MITRE ATT&CK |
|---------|------|----------|--------------|
| TRC-1028 | Sudoers Modification | sudoers 文件被修改 | T1548.003 |
| TRC-1019 | Docker Abuse | 容器内访问 docker.sock | T1068 |
| TRC-1011 | Core Pattern Modification | core_pattern 被修改用于逃逸 | T1611 |
| TRC-1010 | Cgroup Release Agent | cgroup release_agent 被修改 | T1611 |
| TRC-1017 | Kernel Module Loading | 内核模块加载 | T1547.006 |
| TRC-1014 | Disk Mount | 容器挂载宿主机设备 | T1611 |
| TRC-109 | ASLR Inspection | 检查 ASLR 配置（侦察行为） | T1068 |

### 4.2 签名实现示例：Sudoers 修改检测

```go
// signatures/golang/sudoers_modification.go
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
        Name:        "Sudoers file modification detected",
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
        newPath, _ := eventObj.GetStringArgumentByName("new_path")
        // 检查重命名目标
        for _, sudoersDir := range sig.sudoersDirs {
            if strings.HasPrefix(newPath, sudoersDir) {
                return sig.match(event)
            }
        }
    }
    return nil
}
```

### 4.3 签名设计要点

1. **多事件关联**：同时监控 `security_file_open` 和 `security_inode_rename`，防止通过 mv 命令绕过检测
2. **Origin 过滤**：可限定只检测容器内（Origin: "container"）或全局（Origin: "*"）
3. **MITRE ATT&CK 映射**：每个签名都对应 ATT&CK 框架的技术 ID

---

## 5. 检测架构

### 5.1 整体数据流

```
┌─────────────────────────────────────────────────────────────────────────┐
│                            用户空间                                      │
│  ┌────────────────────────────────────────────────────────────────────┐ │
│  │                         Tracee-Rules                               │ │
│  │  ┌───────────────┐  ┌───────────────┐  ┌───────────────────────┐  │ │
│  │  │ 事件解析器     │  │ 签名引擎       │  │ 输出格式化器          │  │ │
│  │  │ (Decoder)     │→│ (Signatures)  │→│ (JSON/Webhook/...)   │  │ │
│  │  └───────────────┘  └───────────────┘  └───────────────────────┘  │ │
│  └────────────────────────────────────────────────────────────────────┘ │
│                                ▲                                         │
│                                │ perf/ring buffer                        │
├────────────────────────────────┼────────────────────────────────────────┤
│                             内核空间                                     │
│  ┌────────────────────────────┴─────────────────────────────────────┐  │
│  │                         Tracee-eBPF                              │  │
│  │                                                                   │  │
│  │  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐  │  │
│  │  │ kprobe/         │  │ kprobe/         │  │ LSM/            │  │  │
│  │  │ commit_creds    │  │ cap_capable     │  │ security_*      │  │  │
│  │  │ (凭证变更)       │  │ (能力请求)       │  │ (安全策略)       │  │  │
│  │  └─────────────────┘  └─────────────────┘  └─────────────────┘  │  │
│  │                                                                   │  │
│  │  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐  │  │
│  │  │ kprobe/         │  │ tracepoint/     │  │ kprobe/         │  │  │
│  │  │ do_init_module  │  │ sched_process_* │  │ switch_task_ns  │  │  │
│  │  │ (模块加载)       │  │ (进程生命周期)   │  │ (命名空间切换)   │  │  │
│  │  └─────────────────┘  └─────────────────┘  └─────────────────┘  │  │
│  └───────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────┘
```

### 5.2 事件与签名的关系

```
                    原始事件                          行为签名
                        │
    commit_creds ───────┼────────────────────→ (直接输出凭证变化)
                        │
    security_file_open ─┼─────┬───────────────→ TRC-1028 Sudoers Modification
                        │     ├───────────────→ TRC-1011 Core Pattern
                        │     ├───────────────→ TRC-109  ASLR Inspection
                        │     └───────────────→ TRC-1019 Docker Abuse
                        │
    security_sb_mount ──┼─────────────────────→ TRC-1014 Disk Mount
                        │
    security_socket_    │
    connect ────────────┼─────────────────────→ TRC-1019 Docker Abuse
                        │
    module_load ────────┼─────────────────────→ TRC-1017 Kernel Module Loading
                        │
    security_inode_     │
    rename ─────────────┴─────────────────────→ TRC-1010 Cgroup Release Agent
```

---

## 6. 检测场景覆盖

### 6.1 常规提权路径

| 提权方式 | 检测事件 | 检测签名 |
|----------|----------|----------|
| sudo/su | commit_creds | - |
| SUID 程序 | commit_creds | - |
| setuid 系统调用 | commit_creds | - |
| 修改 sudoers | security_file_open | TRC-1028 |

### 6.2 内核漏洞利用

| 提权方式 | 检测事件 | 说明 |
|----------|----------|------|
| Dirty COW | commit_creds | 凭证变化被捕获 |
| Dirty Pipe | dirty_pipe_splice | 专用检测事件 |
| overlayfs 漏洞 | commit_creds | 凭证变化被捕获 |
| eBPF 提权 | security_bpf_prog | BPF 程序加载监控 |

### 6.3 容器逃逸

| 逃逸方式 | 检测事件 | 检测签名 |
|----------|----------|----------|
| Docker Socket | security_file_open | TRC-1019 |
| 挂载宿主机设备 | security_sb_mount | TRC-1014 |
| core_pattern | security_file_open | TRC-1011 |
| cgroup release_agent | security_file_open | TRC-1010 |
| nsenter | switch_task_ns | - |

---

## 7. Tracee 检测的优势与局限

### 7.1 优势

1. **全覆盖**：commit_creds 作为咽喉点，无论正常还是异常提权都能捕获
2. **低开销**：只上报有变化的事件，避免海量无用数据
3. **上下文丰富**：包含进程树、容器信息、Kubernetes 信息
4. **可扩展**：签名引擎支持 Go 和 Rego，易于添加新规则

### 7.2 局限

1. **无法阻止**：Tracee 默认只检测不阻止（需启用 LSM 模式）
2. **需要内核支持**：kprobe 需要内核配置支持
3. **绕过可能**：
   - 直接修改 task_struct 而不调用 commit_creds（高级漏洞利用）
   - 使用内核 rootkit 隐藏行为

---

## 8. 最佳实践

### 8.1 推荐启用的事件

```yaml
# 本地提权检测必备事件
events:
  - commit_creds
  - cap_capable
  - security_file_open
  - security_sb_mount
  - security_bpf_prog
  - module_load
  - switch_task_ns
```

### 8.2 告警优先级设置

```
高优先级告警：
  - 容器内 commit_creds 且 new_euid == 0
  - 容器内 TRC-1019 (Docker Abuse)
  - 容器内 TRC-1014 (Disk Mount)
  - 任意 TRC-1017 (Kernel Module Loading)

中优先级告警：
  - TRC-1028 (Sudoers Modification)
  - TRC-1011 (Core Pattern)
  - TRC-1010 (Cgroup Release Agent)

低优先级/信息：
  - 宿主机 commit_creds (可能是正常 sudo)
  - TRC-109 (ASLR Inspection)
```

---

## 9. 总结

Tracee 的本地提权检测采用 **"底层事件采集 + 上层行为分析"** 的分层架构：

1. **底层**：通过 kprobe/commit_creds 监控所有权限变化，这是无法绕过的"咽喉要道"
2. **中层**：通过 LSM hook（security_file_open 等）监控敏感文件/操作访问
3. **上层**：通过 Go 签名引擎进行行为模式匹配，识别具体攻击手法

这种设计既保证了检测的全面性（commit_creds 一网打尽），又提供了丰富的上下文（签名引擎的行为分析），是一个工程实践上非常优秀的检测方案。

---

## 参考资料

- [Tracee 源码](https://github.com/aquasecurity/tracee)
- [Tracee commit_creds 实现](pkg/ebpf/c/tracee.bpf.c:2397)
- [Tracee 签名引擎](signatures/golang/)
- [Linux 内核 cred.c](https://elixir.bootlin.com/linux/latest/source/kernel/cred.c)
