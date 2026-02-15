# 检测设计方法论

> 本文档介绍如何从攻击手法推导出检测规则的系统方法。

---

## 核心思想

**检测设计 = 理解攻击 → 识别特征 → 选择 Hook 点 → 设计规则 → 验证测试**

```
┌─────────────────────────────────────────────────────────────┐
│                    检测设计流程                              │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Step 1          Step 2          Step 3          Step 4    │
│  ┌─────────┐    ┌─────────┐    ┌─────────┐    ┌─────────┐  │
│  │ 理解攻击 │───▶│ 识别特征 │───▶│ 选择Hook │───▶│ 设计规则 │  │
│  └─────────┘    └─────────┘    └─────────┘    └─────────┘  │
│       │              │              │              │        │
│       ▼              ▼              ▼              ▼        │
│  攻击原理        可观测行为       内核函数       检测逻辑      │
│  攻击步骤        系统调用         LSM Hook      告警条件      │
│  攻击目的        文件/进程        Tracepoint    白名单       │
│                                                             │
│                           │                                 │
│                           ▼                                 │
│                      ┌─────────┐                            │
│                      │ Step 5  ��                            │
│                      │ 验证测试 │                            │
│                      └─────────┘                            │
│                           │                                 │
│                           ▼                                 │
│                    复现攻击 → 检测 → 调优                     │
│                                                             │
└────────────────────────────────────────────────────���──────��─┘
```

---

## 目录

1. [Step 1: 理解攻击](#step-1-理解攻击)
2. [Step 2: 识别特征](#step-2-识别特征)
3. [Step 3: 选择 Hook 点](#step-3-选择-hook-点)
4. [Step 4: 设计规则](#step-4-设计规则)
5. [Step 5: 验证测试](#step-5-验证测试)
6. [案例实战](#案例实战)
7. [检测设计模板](#检测设计模板)

---

## Step 1: 理解攻击

### 1.1 分析维度

| 维度 | 问题 | 示例（SUID 提权） |
|------|------|-------------------|
| **目的** | 攻击者想达到什么？ | 获得 root 权限 |
| **前提** | 需要什么条件？ | 存在 SUID 程序、有普通用户 shell |
| **步骤** | 攻击如何进行？ | 找到 SUID 程序 → 利用 → 执行命令 |
| **结果** | 成功后会发生什么？ | 进程 EUID 变成 0 |
| **痕迹** | 会留下什么痕迹？ | 权限变化、异常进程执行 |

### 1.2 攻击分解示例

**攻击：SUID find 命令提权**

```
攻击步骤分解：

1. 信息收集
   └── 执行: find / -perm -u=s -type f 2>/dev/null
   └── 行为: 读取文件系统，查找 SUID 文件

2. 利用 SUID
   └── 执行: find /etc/passwd -exec /bin/sh \;
   └── 行为: execve 执行 find（SUID 程序）
   └── 行为: find 以 root 权限运行
   └── 行为: find 的 -exec 以 root 权限执行 /bin/sh

3. 获得 root shell
   └── 行为: 新进程的 EUID = 0
   └── 行为: commit_creds 被调用，凭证变化
```

### 1.3 参考资源

| 资源 | 说明 |
|------|------|
| [MITRE ATT&CK](https://attack.mitre.org/) | 攻击技术分类和描述 |
| [GTFOBins](https://gtfobins.github.io/) | Unix 二进制利用方法 |
| [HackTricks](https://book.hacktricks.xyz/) | 渗透测试技术手册 |
| CVE 数据库 | 具体漏洞的利用方式 |

---

## Step 2: 识别特征

### 2.1 特征类型

```
┌─────────────────────────────────────────────────────────────┐
│                      可检测特征                              │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
│  │  系统调用   │  │  文件操作   │  │  进程行为   │         │
│  ├─────────────┤  ├─────────────┤  ├─────────────┤         │
│  │ execve     │  │ 读取敏感文件 │  │ 权限变化   │         │
│  │ setuid     │  │ 写入配置   │  │ 异常父子关系│         │
│  │ ptrace     │  │ 创建文件   │  │ 进程名异常 │         │
│  │ mount      │  │ 修改权限   │  │            │         │
│  └─────────────┘  └─────────────┘  └─────────────┘         │
│                                                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
│  │  网络行为   │  │  内核操作   │  │  上下文    │         │
│  ├─────────────┤  ├─────────────┤  ├─────────────┤         │
│  │ 连接建立   │  │ 模块加载   │  │ 是否容器   │         │
│  │ 监听端口   │  │ 内存映射   │  │ 用户身份   │         │
│  │ DNS 查询   │  │ 能力使用   │  │ 时间模式   │         │
│  └─────────────┘  └─────────────┘  └─────────────┘         │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 2.2 特征提取方法

**方法一：动态分析**

```bash
# 使用 strace 观察系统调用
strace -f -e trace=all <attack_command>

# 使用 Tracee 观察事件
sudo tracee --events all --filter 'comm=find'

# 使用 bpftrace 观察
sudo bpftrace -e 'tracepoint:syscalls:sys_enter_* { printf("%s\n", comm); }'
```

**方法二：静态分析**

```bash
# 分析攻击脚本/工具的代码
# 理解它调用了什么函数、访问了什么文件
```

**方法三：文档分析**

```
阅读攻击描述，提取关键行为：
- "利用 SUID 位" → 检查进程的 EUID 变化
- "读取 /etc/shadow" → 监控文件访问
- "加载恶意内核模块" → 监控 init_module
```

### 2.3 特征分类

| 类别 | 特征 | 检测难度 | 误报风险 |
|------|------|----------|----------|
| **直接特征** | 明确的恶意行为（如 EUID 变 0） | 低 | 低 |
| **间接特征** | 攻击的前置/后续行为 | 中 | 中 |
| **组合特征** | 多个行为的组合 | 高 | 低 |
| **异常特征** | 偏离正常基线的行为 | 高 | 高 |

---

## Step 3: 选择 Hook 点

### 3.1 Hook 点决策树

```
                    需要检测什么？
                         │
         ┌───────────────┼───────────────┐
         │               │               │
         ▼               ▼               ▼
      系统调用        文件操作        权限变化
         │               │               │
         ▼               ▼               ▼
    tracepoint      security_*      commit_creds
    sys_enter_*     file_open       cap_capable
                    inode_*
         │               │               │
         ▼               ▼               ▼
    稳定、有参数     有完整路径      覆盖全面
    但无法知道结果   可阻止          但是内部函数
```

### 3.2 常见检测场景的 Hook 点

| 检测场景 | 推荐 Hook 点 | 备选 |
|----------|--------------|------|
| **提权检测** | kprobe/commit_creds | lsm/cred_commit |
| **文件访问** | kprobe/security_file_open | kprobe/vfs_read |
| **进程执行** | tracepoint/sched/sched_process_exec | kprobe/do_execve |
| **网络连接** | kprobe/tcp_connect | tracepoint/sock/inet_sock_set_state |
| **模块加载** | kprobe/do_init_module | tracepoint/module/module_load |
| **能力使用** | kprobe/cap_capable | lsm/capable |

### 3.3 Hook 点选择原则

```
1. 覆盖性：能否覆盖所有攻击路径？
   └── 优先选择"必经之路"（如 commit_creds）

2. 信息量：能获取足够的上下文吗？
   └── 能否获取参数、返回值、调用者信息

3. 稳定性：会随内核版本变化吗？
   └── tracepoint > LSM > kprobe

4. 性能：调用频率高吗？
   └── 高频函数需要更多过滤逻辑
```

---

## Step 4: 设计规则

### 4.1 规则结构

```
规则 = 触发条件 + 上下文过滤 + 告警动作

┌─────────────────────────────────────────────────────────────┐
│  规则定义                                                    │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  WHEN (触发条件)                                            │
│    event.type == "commit_creds"                             │
│    AND event.old_euid != 0                                  │
│    AND event.new_euid == 0                                  │
│                                                             │
│  AND (上下文过滤)                                            │
│    process.comm NOT IN ["sudo", "su", "login"]              │
│    AND process.parent NOT IN ["sshd", "cron"]               │
│    AND (container == true OR process.uid > 1000)            │
│                                                             │
│  THEN (告警动作)                                             │
│    severity = HIGH                                          │
│    alert("Privilege Escalation Detected")                   │
│    include: process_tree, file_context                      │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 4.2 减少误报的技巧

**技巧一：白名单**

```c
// 进程白名单
if (comm == "sudo" || comm == "su" || comm == "login") {
    return;  // 正常的提权程序
}
```

**技巧二：上下文检查**

```c
// 检查父进程
if (parent_comm == "sshd" || parent_comm == "login") {
    severity = INFO;  // 正常的登录流程
}

// 检查是否在容器中
if (is_container && is_privilege_escalation) {
    severity = CRITICAL;  // 容器内提权更可疑
}
```

**技巧三：行为组合**

```c
// 单独的文件读取不告警
// 但 "读取 /etc/shadow" + "之后执行了 shell" = 可疑
if (read_shadow && then_exec_shell) {
    alert();
}
```

**技巧四：频率限制**

```go
// 同一进程短时间内多次触发，只告警一次
if (lastAlert[pid] + 60s > now) {
    return  // 60 秒内不重复告警
}
```

### 4.3 告警级别定义

| 级别 | 含义 | 示例 |
|------|------|------|
| **CRITICAL** | 确定的恶意行为 | 容器内 EUID 变 0 且非白名单进程 |
| **HIGH** | 高度可疑 | 普通程序触发提权 |
| **MEDIUM** | 需要关注 | 敏感文件被读取 |
| **LOW/INFO** | 记录但不告警 | sudo 正常执行 |

---

## Step 5: 验证测试

### 5.1 测试流程

```
1. 搭建测试环境
   └── 隔离的虚拟机
   └── 已知的攻击工具

2. 复现攻击
   └── 执行攻击步骤
   └── 观察检测器输出

3. 验证检测
   └── 是否检测到？
   └── 告警信息是否准确？
   └── 告警级别是否合适？

4. 验证误报
   └── 正常操作是否误报？
   └── 边界情况如何？

5. 调优迭代
   └── 根据结果调整规则
   └── 重复测试
```

### 5.2 测试用例设计

| 类型 | 用例 | 预期结果 |
|------|------|----------|
| **正向测试** | 执行 SUID 提权攻击 | 检测到，告警 HIGH |
| **正向测试** | 利用内核漏洞提权 | 检测到，告警 CRITICAL |
| **负向测试** | 正常执行 sudo | 不告警或 INFO |
| **负向测试** | 正常登录 SSH | 不告警 |
| **边界测试** | sudo 后执行恶意命令 | 视规则而定 |
| **性能测试** | 高频操作下的检测 | 不丢事件，低延迟 |

### 5.3 自动化测试

```bash
#!/bin/bash
# test_privilege_escalation.sh

echo "=== 提权检测测试 ==="

# 测试 1: SUID 提权
echo "[Test 1] SUID 提权"
sudo chmod u+s /tmp/test_binary
su - testuser -c "/tmp/test_binary"
# 预期：检测到 HIGH 告警

# 测试 2: sudo 正常使用
echo "[Test 2] sudo 正常使用"
sudo whoami
# 预期：不告警或 INFO

# 测试 3: 容器内提权
echo "[Test 3] 容器内提权"
docker run --rm ubuntu su -c "id"
# 预期：检测到 CRITICAL 告警
```

---

## 案例实战

### 案例 1：设计 Cgroup 逃逸检测

**Step 1: 理解攻击**

```
Cgroup Release Agent 逃逸：
1. 挂载 cgroup 文件系统
2. 创建子 cgroup
3. 设置 notify_on_release = 1
4. 设置 release_agent = 恶意脚本路径
5. 将进程加入 cgroup 后退出
6. 触发 release_agent，在宿主机执行
```

**Step 2: 识别特征**

| 行为 | 特征 |
|------|------|
| 设置 notify_on_release | 写入 notify_on_release 文件 |
| 设置 release_agent | 写入 release_agent 文件 |
| 在容器内执行 | 进程来自容器 |

**Step 3: 选择 Hook 点**

```
主要检测点：
- kprobe/security_file_open（检测写入 release_agent）
- kprobe/security_inode_rename（检测重命名）
```

**Step 4: 设计规则**

```
WHEN
  event.type == "security_file_open"
  AND event.flags contains O_WRONLY
  AND (event.filename == "release_agent"
       OR event.filename == "notify_on_release")
  AND event.origin == "container"

THEN
  severity = CRITICAL
  alert("Cgroup Escape Attempt")
```

**Step 5: 验证**

```bash
# 在容器中执行逃逸攻击
docker run --privileged -it ubuntu bash
# 执行攻击步骤...
# 观察检测器是否告警
```

---

### 案例 2：设计反弹 Shell 检测

**Step 1: 理解攻击**

```
反弹 Shell 特征：
- 进程执行 /bin/sh 或 /bin/bash
- stdin/stdout/stderr 重定向到网络 socket
- 连接到外部 IP
```

**Step 2: 识别特征**

| 特征 | 检测方式 |
|------|----------|
| 执行 shell | execve + comm 检查 |
| 网络连接 | tcp_connect |
| 文件描述符重定向 | dup2 到 socket |

**Step 3: 选择 Hook 点**

```
组合检测：
- tracepoint/sched/sched_process_exec
- kprobe/tcp_connect
- 关联分析（同一进程）
```

**Step 4: 设计规则**

```
WHEN
  event.type == "process_exec"
  AND event.filename IN ["/bin/sh", "/bin/bash", "/bin/dash"]
  AND process.has_network_socket == true
  AND process.socket.remote_ip NOT IN whitelist

THEN
  severity = HIGH
  alert("Reverse Shell Detected")
```

---

## 检测设计模板

### 检测规则设计文档模板

```markdown
# 检测规则：[规则名称]

## 1. 攻击描述

### 攻击名称
[攻击的名称/编号]

### MITRE ATT&CK 映射
- 战术：[Tactic]
- 技术：[Technique ID]

### 攻击原理
[简要描述攻击原理]

### 攻击步骤
1. [步骤 1]
2. [步骤 2]
3. ...

## 2. 检测特征

| 特征类型 | 特征描述 | 可靠性 |
|----------|----------|--------|
| [特征 1] | [描述]   | 高/中/低 |
| ...      | ...      | ...    |

## 3. Hook 点

| Hook 点 | 类型 | 获取信息 |
|---------|------|----------|
| [Hook]  | [类型] | [信息]  |

## 4. 检测规则

### 触发条件
```
[伪代码描述触发条件]
```

### 过滤条件（减少误报）
```
[白名单/上下文过滤]
```

### 告警级别
- 条件 A：CRITICAL
- 条件 B：HIGH
- 默认：MEDIUM

## 5. 测试用例

| 用例 | 操作 | 预期结果 |
|------|------|----------|
| 正向测试 | [操作] | 检测到 |
| 负向测试 | [操作] | 不告警 |

## 6. 已知限制

- [限制 1]
- [限制 2]

## 7. 参考资料

- [参考 1]
- [参考 2]
```

---

## 快速参考

### 攻击类型 → Hook 点速查

| 攻击类型 | 推荐 Hook 点 |
|----------|--------------|
| 提权（UID 变化） | kprobe/commit_creds |
| 提权（Capability） | kprobe/cap_capable |
| 敏感文件读取 | kprobe/security_file_open |
| 敏感文件写入 | kprobe/security_file_open |
| 进程注入 | kprobe/ptrace_attach |
| 内核模块加载 | kprobe/do_init_module |
| 容器逃逸（cgroup） | kprobe/security_file_open |
| 容器逃逸（mount） | kprobe/security_sb_mount |
| 反弹 Shell | tracepoint/exec + kprobe/tcp_connect |
| 命令执行 | tracepoint/sched/sched_process_exec |

### 检测设计 Checklist

- [ ] 理解了攻击的原理和步骤
- [ ] 识别了关键的检测特征
- [ ] 选择了合适的 Hook 点
- [ ] 设计了触发条件
- [ ] 添加了白名单减少误报
- [ ] 定义了合适的告警级别
- [ ] 编写了正向测试用例
- [ ] 编写了负向测试用例
- [ ] 验证了检测效果
- [ ] 记录了已知限制

---

## 下一步

- [从零搭建检测工具](tutorial-ebpf-detector-from-scratch.md) - 实现你设计的规则
- [签名引擎详解](signature-engine.md) - 学习 Tracee 的签名系统
- [提权攻防实验](lab-01-privilege-escalation.md) - 实践检测设计
- [容器逃逸攻防实验](lab-03-container-escape.md) - 实践 Cgroup 逃逸检测（对应案例 1）

---

_最后更新：2026-02-15_
