# Tracee 源码学习实战练习指南

本文档提供了一系列实战练习，帮助你深入理解 Tracee 源码。每个练习都包含明确的目标、涉及的源文件、具体任务和验证方法。

---

## 📚 如何使用本指南

1. **按顺序完成练习**：练习按难度递增排列
2. **动手实践**：不要只是阅读代码，要运行、修改、调试
3. **记录笔记**：记录你的发现、疑问和理解
4. **验证结果**：每个练习都有验证步骤确保你真正理解

---

## 第一阶段：初识 Tracee（对应 Stage 1）

### 练习 1.1：追踪第一个系统调用

**目标**：理解 Tracee 如何捕获和展示 execve 系统调用

**涉及文件**：
- `pkg/ebpf/c/tracee.bpf.c` (eBPF C 代码)
- `pkg/events/events.go` (事件定义)
- `cmd/tracee/cmd/root.go` (命令行入口)

**任务步骤**：

1. **运行基础追踪命令**：
```bash
# 只追踪 execve 事件
sudo ./dist/tracee --events execve

# 在另一个终端执行一些命令
ls /tmp
echo "hello"
```

2. **阅读 execve 事件定义**：
- 打开 `pkg/events/events.go`
- 搜索 `Execve` 事件定义
- 理解事件 ID、参数定义、属性

3. **定位 eBPF 捕获点**：
- 打开 `pkg/ebpf/c/tracee.bpf.c`
- 搜索 `sched_process_exec` 或 `sys_enter_execve`
- 阅读 eBPF 程序如何捕获参数

4. **修改代码添加日志**：
在 `pkg/ebpf/c/tracee.bpf.c` 中找到 execve 相关函数，添加简单的日志（可选）

**验证问题**：
- [ ] execve 事件有多少个参数？每个参数的含义是什么？
- [ ] eBPF 程序挂载在哪个内核挂载点上？
- [ ] 事件数据如何从内核传递到用户空间？

**扩展思考**：
- 为什么 Tracee 选择 `sched_process_exec` 而不是 `sys_enter_execve`？
- 两者有什么区别？

---

### 练习 1.2：理解事件过滤机制

**目标**：学习如何使用策略过滤特定进程或容器的事件

**涉及文件**：
- `pkg/policy/policy.go` (策略定义)
- `pkg/ebpf/c/maps.bpf.h` (BPF Maps 定义)
- `pkg/ebpf/processor.go` (事件处理器)

**任务步骤**：

1. **创建简单策略文件** `test-policy.yaml`：
```yaml
apiVersion: tracee.aquasec.com/v1beta1
kind: Policy
metadata:
  name: test-execve
  annotations:
    description: 只追踪 UID=1000 的用户
spec:
  scope:
    - uid=1000
  rules:
    - event: execve
    - event: openat
```

2. **使用策略运行 Tracee**：
```bash
sudo ./dist/tracee --policy test-policy.yaml
```

3. **阅读策略解析代码**：
- 打开 `pkg/policy/policy.go`
- 找到 `Parse` 或 `FromYAML` 函数
- 理解如何将 YAML 转换为内部数据结构

4. **查看 BPF Maps 实现**：
- 打开 `pkg/ebpf/c/maps.bpf.h`
- 找到策略相关的 map（如 `policies_config`）
- 理解内核如何访问这些过滤规则

**验证问题**：
- [ ] Scope 过滤在哪里执行（内核态还是用户态）？
- [ ] 如果一个事件匹配多个策略会发生什么？
- [ ] BPF Map 使用什么数据结构？

**实战任务**：
编写一个策略，只追踪：
- 容器内的进程
- 访问 `/etc` 目录的文件操作
- 不包括 UID=0 的操作

---

### 练习 1.3：探索输出格式

**目标**：理解不同输出格式的实现原理

**涉及文件**：
- `pkg/printer/printer.go` (打印接口)
- `pkg/printer/table.go` (表格输出)
- `pkg/printer/json.go` (JSON 输出)

**任务步骤**：

1. **测试不同输出格式**：
```bash
# 表格格式（默认）
sudo ./dist/tracee --events execve --output table

# JSON 格式
sudo ./dist/tracee --events execve --output json

# JSON 格式输出到文件
sudo ./dist/tracee --events execve --output json:/tmp/tracee-output.json
```

2. **阅读 Printer 接口**：
- 打开 `pkg/printer/printer.go`
- 理解 `Printer` 接口定义
- 查看 `New()` 工厂函数如何选择实现

3. **对比不同实现**：
- 阅读 `table.go` 中的 `Print()` 方法
- 阅读 `json.go` 中的 `Print()` 方法
- 理解如何从统一的 `Event` 结构生成不同格式

**验证问题**：
- [ ] 添加新的输出格式需要实现哪些接口？
- [ ] 事件时间戳是如何格式化的？
- [ ] JSON 输出如何处理嵌套数据结构？

**实战任务**：
设计一个新的输出格式（CSV），画出实现步骤的流程图。

---

## 第二阶段：深入 eBPF（对应 Stage 2-3）

### 练习 2.1：理解 BPF Map 的使用

**目标**：掌握不同类型 BPF Map 的使用场景

**涉及文件**：
- `pkg/ebpf/c/maps.bpf.h` (Map 定义)
- `pkg/ebpf/maps.go` (Go 端 Map 操作)
- `pkg/ebpf/c/common/buffer.h` (环形缓冲区)

**任务步骤**：

1. **列举所有 BPF Maps**：
```bash
# 在源码中搜索所有 Map 定义
grep -n "struct bpf_map_def" pkg/ebpf/c/maps.bpf.h
# 或使用新格式
grep -n "SEC(\".maps\")" pkg/ebpf/c/tracee.bpf.c
```

2. **分类 Maps**：
创建一个表格，分类所有 Maps：
- Hash Maps：用于快速查找
- Array Maps：固定大小，索引访问
- Perf/Ring Buffer：事件传递
- LRU Maps：缓存最近使用

3. **阅读一个 Map 的完整生命周期**：
选择 `events_map`（事件配置 Map）：
- 在 C 代码中找到定义
- 在 Go 代码中找到初始化代码
- 找到写入数据的代码
- 找到 eBPF 程序中读取的代码

4. **动手实验**：
```bash
# 运行 Tracee
sudo ./dist/tracee --events execve &

# 使用 bpftool 查看 Maps
sudo bpftool map list | grep tracee
sudo bpftool map dump name events_map
```

**验证问题**：
- [ ] `events_map` 的 key 和 value 是什么类型？
- [ ] 为什么使用 Hash Map 而不是 Array？
- [ ] Perf Buffer 和 Ring Buffer 有什么区别？

**实战任务**：
画一个序列图，展示一个事件从 eBPF 程序通过 Perf Buffer 传递到用户空间的完整过程。

---

### 练习 2.2：追踪一个 Kprobe 的实现

**目标**：理解动态追踪点（Kprobe）的工作原理

**涉及文件**：
- `pkg/ebpf/c/tracee.bpf.c` (Kprobe 程序)
- `pkg/ebpf/probes/trace.go` (Probe 附加逻辑)
- `pkg/ebpf/probes/probe_group.go` (Probe 管理)

**任务步骤**：

1. **选择一个 Kprobe**：
选择 `security_file_open` 作为研究对象

2. **找到 eBPF 程序**：
```bash
# 搜索 security_file_open
grep -n "security_file_open" pkg/ebpf/c/tracee.bpf.c
```

3. **阅读 C 代码实现**：
- 理解函数签名
- 查看如何获取参数（`ctx->args[0]`, `ctx->args[1]` 等）
- 理解如何提交事件到 Perf Buffer

4. **追踪 Go 端附加逻辑**：
- 打开 `pkg/ebpf/probes/trace.go`
- 找到 `TraceProbe` 结构体的 `attach()` 方法
- 理解如何使用 libbpfgo 附加 Kprobe

5. **查看 Handle 定义**：
- 打开 `pkg/ebpf/probes/probes.go`
- 找到 `SecurityFileOpen` Handle 定义
- 理解 Handle 在系统中的作用

**验证问题**：
- [ ] Kprobe 在什么时机被附加到内核？
- [ ] 如果内核函数不存在会发生什么？
- [ ] Kprobe 和 Kretprobe 有什么区别？

**实战任务**：
修改代码，添加一个新的 Kprobe 追踪点，追踪 `do_sys_openat2` 函数。

---

### 练习 2.3：分析事件依赖关系

**目标**：理解事件之间的依赖关系和自动化 Probe 附加机制

**涉及文件**：
- `pkg/events/dependencies/dependencies.go` (依赖图)
- `pkg/ebpf/tracee.go` (订阅机制)
- `pkg/events/derive.go` (衍生事件)

**任务步骤**：

1. **找到一个有依赖的事件**：
- 打开 `pkg/events/events.go`
- 搜索 `Dependencies` 字段
- 选择一个有依赖的事件，如 `ProcessTree`

2. **理解依赖图**：
- 打开 `pkg/events/dependencies/dependencies.go`
- 找到 `InitializeDependencies()` 函数
- 理解如何构建依赖图

3. **追踪订阅机制**：
- 打开 `pkg/ebpf/tracee.go`
- 找到 `attachProbes()` 函数（约 1352 行）
- 理解 `SubscribeAdd` 回调如何工作

4. **实验依赖附加**：
```bash
# 只启用一个衍生事件
sudo ./dist/tracee --events process_tree

# 观察哪些 Probes 被自动附加
# 查看日志输出
```

5. **阅读衍生事件代码**：
- 打开 `pkg/events/derive.go`
- 找到 `ProcessTreeEvent` 的实现
- 理解如何从基础事件生成衍生事件

**验证问题**：
- [ ] `process_tree` 事件依赖哪些基础事件？
- [ ] 依赖图是如何遍历的（DFS 还是 BFS）？
- [ ] 如果循环依赖会发生什么？

**实战任务**：
画一个依赖图，展示以下事件的依赖关系：
- `container_create`
- `sched_process_exec`
- `cgroup_attach_task`
- `process_tree`

---

## 第三阶段：容器检测与策略（对应 Stage 3-4）

### 练习 3.1：容器识别机制

**目标**：理解 Tracee 如何识别和追踪容器

**涉及文件**：
- `pkg/containers/runtime.go` (容器运行时接口)
- `pkg/ebpf/c/tracee.bpf.c` (CGroup 相关代码)
- `pkg/events/containers.go` (容器事件)

**任务步骤**：

1. **启动容器追踪**：
```bash
# 只追踪容器内的事件
sudo ./dist/tracee --scope container --events execve

# 在另一个终端启动容器
docker run --rm -it ubuntu bash
```

2. **阅读 CGroup 检测代码**：
- 打开 `pkg/ebpf/c/tracee.bpf.c`
- 搜索 `get_task_cgroup_id` 或类似函数
- 理解如何从 task_struct 获取 CGroup ID

3. **理解容器运行时接口**：
- 打开 `pkg/containers/runtime.go`
- 查看 `Runtime` 接口定义
- 理解支持哪些容器运行时（Docker, containerd, CRI-O）

4. **追踪容器元数据获取**：
- 查看如何通过 CGroup ID 查询容器 ID
- 理解容器名称、镜像等元数据的获取流程

5. **实验 CGroup 过滤**：
```bash
# 创建测试容器
docker run -d --name test-container nginx

# 获取容器 ID
CONTAINER_ID=$(docker inspect -f '{{.Id}}' test-container)

# 只追踪特定容器
sudo ./dist/tracee --scope container=test-container --events execve
```

**验证问题**：
- [ ] CGroup ID 和容器 ID 的关系是什么？
- [ ] 如何区分容器和虚拟机？
- [ ] 容器元数据缓存在哪里？

**实战任务**：
画一个时序图，展示从容器启动到 Tracee 识别容器的完整流程。

---

### 练习 3.2：复杂策略设计

**目标**：设计和实现复杂的多条件策略

**涉及文件**：
- `pkg/policy/v1beta1/policy.go` (策略结构)
- `pkg/filters/*.go` (各种过滤器)
- `examples/policies/` (策略示例)

**任务步骤**：

1. **研究现有策略**：
```bash
# 查看示例策略
ls examples/policies/
cat examples/policies/container-security.yaml
```

2. **设计一个安全策略**：
目标：检测容器逃逸尝试
要求：
- 只监控容器内进程
- 追踪危险系统调用（unshare, mount, ptrace）
- 追踪敏感文件访问（/proc/*/ns/*, /dev/*)
- 排除已知安全进程（kubelet, containerd）

3. **编写策略文件** `container-escape-detection.yaml`：
```yaml
apiVersion: tracee.aquasec.com/v1beta1
kind: Policy
metadata:
  name: container-escape-detection
  annotations:
    description: 检测容器逃逸尝试
spec:
  scope:
    - container
    - not_comm=kubelet,containerd,dockerd
  rules:
    # 危险系统调用
    - event: unshare
      filters:
        - args.flags.CLONE_NEWNS=true

    # 挂载操作
    - event: mount
      filters:
        - not_data.mountpoint=/dev/*

    # 命名空间操作
    - event: openat
      filters:
        - data.pathname=/proc/*/ns/*

    # Ptrace 调试
    - event: ptrace
```

4. **测试策略**：
```bash
# 运行策略
sudo ./dist/tracee --policy container-escape-detection.yaml

# 在容器中测试
docker run --rm -it ubuntu bash
# 在容器内执行
unshare -m bash
mount --bind /tmp /tmp
```

5. **阅读过滤器实现**：
- 打开 `pkg/filters/string_filter.go`
- 打开 `pkg/filters/int_filter.go`
- 理解不同过滤器类型的实现

**验证问题**：
- [ ] 过滤器在哪个阶段执行（内核态/用户态）？
- [ ] `not_comm` 过滤器如何实现？
- [ ] 如何添加自定义过滤器？

**实战任务**：
设计一个策略文件，实现以下需求：
- 监控所有容器的网络连接
- 只关注外部 IP（非 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16）
- 追踪 DNS 查询
- 记录所有 443 端口连接

---

### 练习 3.3：自定义数据源

**目标**：理解并实现自定义数据源（Data Source）

**涉及文件**：
- `pkg/ebpf/c/types.h` (数据源类型定义)
- `pkg/ebpf/initialization/manager.go` (数据源管理)
- `pkg/ebpf/datasource/` (数据源实现)

**任务步骤**：

1. **了解现有数据源**：
```bash
# 列出所有数据源实现
ls pkg/ebpf/datasource/
```

2. **阅读一个数据源实现**：
选择 `dns_cache.go` 作为示例：
- 理解数据源接口
- 查看如何注册数据源
- 理解数据源如何被事件使用

3. **设计新数据源**：
目标：创建一个进程命令行缓存数据源
功能：缓存进程 PID 到完整命令行的映射

4. **画出数据流图**：
展示：
- 数据源初始化
- 数据写入时机
- 数据查询接口
- 数据清理机制

5. **阅读内核端数据源使用**：
- 打开 `pkg/ebpf/c/tracee.bpf.c`
- 搜索数据源相关的 Map 访问
- 理解 eBPF 程序如何读取数据源

**验证问题**：
- [ ] 数据源存储在哪里（Map 类型）？
- [ ] 数据源的生命周期是什么？
- [ ] 如何处理数据源溢出？

**实战任务**：
设计一个 "HTTP 连接追踪" 数据源，记录每个进程的 HTTP 请求目标。

---

## 第四阶段：签名引擎（对应 Stage 4-5）

### 练习 4.1：理解签名引擎架构

**目标**：掌握签名引擎的工作原理和扩展机制

**涉及文件**：
- `pkg/signatures/engine/engine.go` (引擎核心)
- `pkg/signatures/signature/signature.go` (签名接口)
- `signatures/golang/` (Go 签名示例)

**任务步骤**：

1. **列举所有内置签名**：
```bash
# 查看 Go 签名
ls signatures/golang/

# 查看 Rego 签名
ls signatures/rego/
```

2. **阅读签名引擎初始化**：
- 打开 `pkg/signatures/engine/engine.go`
- 找到 `NewEngine()` 函数
- 理解签名加载流程

3. **研究一个简单签名**：
选择 `anti_debugging.go`：
```bash
cat signatures/golang/anti_debugging.go
```
理解：
- `GetMetadata()` 方法
- `GetSelectedEvents()` 方法
- `OnEvent()` 方法
- `OnSignal()` 方法

4. **追踪事件到签名的流程**：
- 打开 `pkg/ebpf/tracee.go`
- 找到事件处理管道
- 理解事件如何路由到签名引擎

5. **测试签名检测**：
```bash
# 启用所有签名
sudo ./dist/tracee --signatures

# 在另一个终端触发检测
# 例如：反调试检测
ptrace PTRACE_TRACEME 0 0 0
```

**验证问题**：
- [ ] 签名引擎在哪个线程/协程运行？
- [ ] 多个签名如何并发处理同一事件？
- [ ] 签名如何维护状态？

**实战任务**：
画一个流程图，展示一个事件从捕获到触发签名告警的完整路径。

---

### 练习 4.2：编写 Go 签名

**目标**：实现一个自定义 Go 签名检测特定攻击模式

**涉及文件**：
- `signatures/golang/` (示例目录)
- `pkg/signatures/signature/signature.go` (接口定义)
- `types/protocol/protocol.go` (事件协议)

**任务步骤**：

1. **设计签名需求**：
目标：检测 "可疑的 SSH 密钥读取"
触发条件：
- 非 SSH 相关进程
- 读取 `~/.ssh/id_rsa` 或 `~/.ssh/id_ed25519`
- 进程可执行文件不在 `/usr/bin/ssh*`

2. **创建签名文件** `signatures/golang/suspicious_ssh_key_access.go`：
```go
package main

import (
    "fmt"
    "strings"

    "github.com/aquasecurity/tracee/signatures/helpers"
    "github.com/aquasecurity/tracee/types/detect"
    "github.com/aquasecurity/tracee/types/protocol"
    "github.com/aquasecurity/tracee/types/trace"
)

type SuspiciousSshKeyAccess struct {
    cb detect.SignatureHandler
}

func (s *SuspiciousSshKeyAccess) Init(ctx detect.SignatureContext) error {
    s.cb = ctx.Callback
    return nil
}

func (s *SuspiciousSshKeyAccess) GetMetadata() (detect.SignatureMetadata, error) {
    return detect.SignatureMetadata{
        ID:          "TRC-CUSTOM-001",
        Version:     "1.0.0",
        Name:        "Suspicious SSH Key Access",
        EventName:   "suspicious_ssh_key_access",
        Description: "Detects non-SSH processes reading private SSH keys",
        Tags:        []string{"credential_access", "ssh"},
        Properties: map[string]interface{}{
            "Severity":     3,
            "Category":     "credential-access",
            "Technique":    "T1552.004",
            "MITRE ATT&CK": "Unsecured Credentials: Private Keys",
        },
    }, nil
}

func (s *SuspiciousSshKeyAccess) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
    return []detect.SignatureEventSelector{
        {Source: "tracee", Name: "security_file_open"},
        {Source: "tracee", Name: "openat"},
    }, nil
}

func (s *SuspiciousSshKeyAccess) OnEvent(event protocol.Event) error {
    eventObj, ok := event.Payload.(trace.Event)
    if !ok {
        return fmt.Errorf("invalid event")
    }

    // 获取进程信息
    processPath, err := helpers.GetTraceeStringArgumentByName(eventObj, "pathname")
    if err != nil {
        return nil
    }

    // 检查是否是 SSH 私钥
    if !strings.Contains(processPath, "/.ssh/id_") {
        return nil
    }
    if !strings.HasSuffix(processPath, "id_rsa") &&
       !strings.HasSuffix(processPath, "id_ed25519") &&
       !strings.HasSuffix(processPath, "id_ecdsa") {
        return nil
    }

    // 获取执行程序路径
    exePath := eventObj.ProcessName

    // 检查是否是 SSH 相关程序
    if strings.HasPrefix(exePath, "/usr/bin/ssh") ||
       strings.HasPrefix(exePath, "/usr/bin/scp") ||
       strings.HasPrefix(exePath, "/usr/bin/sftp") {
        return nil
    }

    // 触发告警
    metadata, _ := s.GetMetadata()
    s.cb(&detect.Finding{
        SigMetadata: metadata,
        Event:       event,
        Data: map[string]interface{}{
            "ssh_key_path": processPath,
            "process_path": exePath,
            "process_name": eventObj.ProcessName,
            "pid":          eventObj.ProcessID,
            "uid":          eventObj.UserID,
        },
    })

    return nil
}

func (s *SuspiciousSshKeyAccess) OnSignal(signal detect.Signal) error {
    return nil
}

func (s *SuspiciousSshKeyAccess) Close() {}
```

3. **编译和测试**：
```bash
# 构建 Tracee（包含新签名）
make build

# 测试签名
sudo ./dist/tracee --signatures TRC-CUSTOM-001

# 触发检测
cat ~/.ssh/id_rsa
```

4. **添加单元测试** `signatures/golang/suspicious_ssh_key_access_test.go`：
```go
package main

import (
    "testing"

    "github.com/aquasecurity/tracee/types/protocol"
    "github.com/aquasecurity/tracee/types/trace"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

func TestSuspiciousSshKeyAccess(t *testing.T) {
    testCases := []struct {
        name     string
        event    trace.Event
        expected bool
    }{
        {
            name: "should trigger - cat reading id_rsa",
            event: trace.Event{
                ProcessName: "cat",
                ProcessID:   1234,
                UserID:      1000,
                Args: []trace.Argument{
                    {
                        Name:  "pathname",
                        Value: "/home/user/.ssh/id_rsa",
                    },
                },
            },
            expected: true,
        },
        {
            name: "should not trigger - ssh reading id_rsa",
            event: trace.Event{
                ProcessName: "/usr/bin/ssh",
                ProcessID:   1234,
                UserID:      1000,
                Args: []trace.Argument{
                    {
                        Name:  "pathname",
                        Value: "/home/user/.ssh/id_rsa",
                    },
                },
            },
            expected: false,
        },
    }

    for _, tc := range testCases {
        t.Run(tc.name, func(t *testing.T) {
            // 测试实现
        })
    }
}
```

**验证问题**：
- [ ] 签名如何访问事件参数？
- [ ] 如何处理签名错误（返回 error）？
- [ ] 签名性能如何优化？

**实战任务**：
实现一个签名，检测以下攻击模式：
- 进程注入（ptrace + process_vm_writev）
- 反弹 Shell（socket + dup2 + execve）
- 文件加密勒索软件（大量文件重命名 + 加密特征）

---

### 练习 4.3：Rego 签名开发

**目标**：使用 Rego 语言编写声明式签名

**涉及文件**：
- `signatures/rego/` (Rego 签名目录)
- `pkg/signatures/rego/rego.go` (Rego 引擎)

**任务步骤**：

1. **学习 Rego 基础**：
```bash
# 查看示例 Rego 签名
cat signatures/rego/container_escape_attempt.rego
```

2. **理解 Tracee Rego 输入**：
输入结构：
```json
{
  "eventName": "openat",
  "args": [
    {"name": "pathname", "value": "/etc/passwd"},
    {"name": "flags", "value": "O_RDONLY"}
  ],
  "metadata": {
    "processName": "cat",
    "pid": 1234,
    "uid": 0
  }
}
```

3. **编写 Rego 签名** `signatures/rego/sensitive_file_access.rego`：
```rego
package tracee.TRC_CUSTOM_002

__rego_metadoc__ := {
    "id": "TRC-CUSTOM-002",
    "version": "1.0.0",
    "name": "Sensitive File Access",
    "eventName": "sensitive_file_access",
    "description": "Detects access to sensitive system files",
    "tags": ["credential_access", "discovery"],
    "properties": {
        "Severity": 2,
        "Category": "credential-access",
        "Technique": "T1552",
        "MITRE ATT&CK": "Unsecured Credentials"
    }
}

# 敏感文件列表
sensitive_files := {
    "/etc/shadow",
    "/etc/gshadow",
    "/etc/sudoers",
    "/root/.ssh/authorized_keys",
    "/root/.bash_history"
}

# 白名单进程
whitelist_processes := {
    "sudo",
    "passwd",
    "sshd",
    "systemd"
}

# 匹配的事件类型
eventSelectors := [
    {
        "source": "tracee",
        "name": "openat"
    },
    {
        "source": "tracee",
        "name": "security_file_open"
    }
]

# 主检测逻辑
tracee_selected_events[eventSelector] {
    eventSelector := eventSelectors[_]
}

tracee_match {
    # 获取文件路径
    pathname := input.args[_].value

    # 检查是否是敏感文件
    is_sensitive(pathname)

    # 检查是否是白名单进程
    not is_whitelisted(input.processName)

    # 检查是否是 root 用户（排除）
    input.uid != 0
}

is_sensitive(path) {
    sensitive_files[path]
}

is_sensitive(path) {
    # 支持通配符匹配
    startswith(path, "/root/.ssh/")
}

is_whitelisted(process) {
    whitelist_processes[process]
}

is_whitelisted(process) {
    # 支持路径匹配
    startswith(process, "/usr/sbin/")
}
```

4. **测试 Rego 签名**：
```bash
# 使用 OPA 测试
opa test signatures/rego/

# 在 Tracee 中测试
sudo ./dist/tracee --signatures TRC-CUSTOM-002

# 触发检测
cat /etc/shadow  # 应该触发告警
```

5. **编写 Rego 测试** `signatures/rego/sensitive_file_access_test.rego`：
```rego
package tracee.TRC_CUSTOM_002

test_sensitive_file_cat {
    tracee_match with input as {
        "eventName": "openat",
        "processName": "cat",
        "uid": 1000,
        "args": [
            {"name": "pathname", "value": "/etc/shadow"}
        ]
    }
}

test_whitelist_sudo {
    not tracee_match with input as {
        "eventName": "openat",
        "processName": "sudo",
        "uid": 1000,
        "args": [
            {"name": "pathname", "value": "/etc/shadow"}
        ]
    }
}

test_root_user_excluded {
    not tracee_match with input as {
        "eventName": "openat",
        "processName": "cat",
        "uid": 0,
        "args": [
            {"name": "pathname", "value": "/etc/shadow"}
        ]
    }
}
```

**验证问题**：
- [ ] Go 签名和 Rego 签名的性能差异？
- [ ] Rego 签名如何维护状态？
- [ ] 如何在 Rego 中使用外部数据？

**实战任务**：
编写一个 Rego 签名，检测：
- Kubernetes Secret 文件访问
- etcd 数据库访问
- Docker socket 滥用

---

## 第五阶段：高级主题（对应 Stage 5-6）

### 练习 5.1：性能分析与优化

**目标**：分析 Tracee 性能瓶颈并进行优化

**涉及文件**：
- `pkg/metrics/metrics.go` (指标收集)
- `pkg/ebpf/processor.go` (事件处理器)

**任务步骤**：

1. **启用性能分析**：
```bash
# 启用 pprof
sudo ./dist/tracee --events execve,openat --pprof &

# 访问 pprof 端点
go tool pprof http://localhost:6060/debug/pprof/profile?seconds=30

# 或生成火焰图
wget http://localhost:6060/debug/pprof/profile?seconds=30 -O tracee.prof
go tool pprof -http=:8080 tracee.prof
```

2. **压力测试**：
```bash
# 生成大量事件
stress-ng --fork 100 --timeout 60s &

# 观察 Tracee 性能
top -p $(pidof tracee)
```

3. **分析 Perf Buffer 配置**：
- 打开 `pkg/ebpf/c/common/buffer.h`
- 理解 Perf Buffer 大小配置
- 实验不同缓冲区大小的影响

4. **优化 eBPF 程序**：
选择一个热点 eBPF 程序，分析优化机会：
- 减少不必要的 Map 查找
- 使用内联函数减少调用开销
- 优化字符串拷贝

5. **用户空间优化**：
- 分析事件处理管道
- 识别序列化/反序列化开销
- 优化 JSON 编码

**验证问题**：
- [ ] 最大事件吞吐量是多少？
- [ ] CPU 使用率的主要贡献者是什么？
- [ ] 内存使用模式如何？

**实战任务**：
编写一个性能测试脚本，对比：
- 不同 Perf Buffer 大小
- 不同事件过滤策略
- 不同输出格式
的性能影响。

---

### 练习 5.2：添加新事件

**目标**：从零实现一个新的 Tracee 事件

**涉及文件**：
- `pkg/events/events.go` (事件定义)
- `pkg/ebpf/c/tracee.bpf.c` (eBPF 实现)
- `pkg/ebpf/events_pipeline.go` (事件解码)
- `pkg/ebpf/probes/probe_group.go` (Probe 注册)

**任务步骤**：

1. **选择要追踪的内核函数**：
目标：追踪内核模块加载 `init_module` 系统调用

2. **定义事件结构** (修改 `pkg/events/events.go`)：
```go
// 在适当位置添加事件 ID
InitModule: {
    ID32Bit: sys32Undefined,
    Name:    "init_module",
    Sets:    []string{"syscalls", "system"},
    Params: []trace.ArgMeta{
        {Type: "void*", Name: "module_image"},
        {Type: "unsigned long", Name: "len"},
        {Type: "const char*", Name: "param_values"},
    },
    Dependencies: Dependencies{
        Probes: []Probe{
            {Handle: probes.SysInitModule, Required: true},
        },
    },
}
```

3. **添加 Probe Handle** (修改 `pkg/ebpf/probes/probes.go`)：
```go
const (
    // ... 现有 Handles
    SysInitModule Handle = iota + 1000
)
```

4. **实现 eBPF 程序** (修改 `pkg/ebpf/c/tracee.bpf.c`)：
```c
SEC("raw_tracepoint/sys_enter")
int syscall__init_module(struct bpf_raw_tracepoint_args *ctx)
{
    // 检查系统调用号
    int id = get_syscall_id_from_regs(ctx);
    if (id != __NR_init_module)
        return 0;

    // 创建事件
    event_data_t data = {};
    init_event(&data, ctx);
    data.event_id = INIT_MODULE;

    // 获取参数
    struct pt_regs *regs = (struct pt_regs *)ctx->args[0];
    void *module_image = (void *)PT_REGS_PARM1(regs);
    unsigned long len = PT_REGS_PARM2(regs);
    const char *param_values = (const char *)PT_REGS_PARM3(regs);

    // 保存参数到事件
    save_ptr_to_buf(&data, module_image, 0);
    save_u64_to_buf(&data, len, 1);
    save_str_to_buf(&data, param_values, 2);

    // 提交事件
    events_perf_submit(&data);
    return 0;
}
```

5. **注册 Probe** (修改 `pkg/ebpf/probes/probe_group.go`)：
```go
func NewDefaultProbeGroup(...) (*ProbeGroup, error) {
    allProbes := map[Handle]Probe{
        // ... 现有 probes
        SysInitModule: NewTraceProbe(RawTracepoint, "raw_syscalls:sys_enter", "syscall__init_module"),
    }
    // ...
}
```

6. **实现事件解码** (修改 `pkg/ebpf/events_processor.go`)：
```go
func (p *EventProcessor) processInitModule(event *trace.Event) error {
    moduleImage, err := p.GetArgs(event, 0)
    if err != nil {
        return err
    }

    len, err := p.GetArgs(event, 1)
    if err != nil {
        return err
    }

    paramValues, err := p.GetArgs(event, 2)
    if err != nil {
        return err
    }

    event.Args = []trace.Argument{
        {ArgMeta: event.Params[0], Value: moduleImage},
        {ArgMeta: event.Params[1], Value: len},
        {ArgMeta: event.Params[2], Value: paramValues},
    }

    return nil
}
```

7. **编译和测试**：
```bash
# 构建
make build

# 测试
sudo ./dist/tracee --events init_module

# 在另一个终端加载模块
sudo modprobe dummy
```

**验证问题**：
- [ ] 事件参数是否正确捕获？
- [ ] 性能影响如何？
- [ ] 兼容性如何（不同内核版本）？

**实战任务**：
添加一个新事件，追踪以下之一：
- BPF 程序加载（`bpf` 系统调用）
- Seccomp 过滤器设置（`seccomp` 系统调用）
- 用户命名空间创建（`unshare` with CLONE_NEWUSER）

---

### 练习 5.3：集成外部系统

**目标**：实现 Tracee 与外部安全系统的集成

**涉及文件**：
- `pkg/sinks/` (输出接收器)
- `pkg/webhooks/` (Webhook 集成)

**任务步骤**：

1. **研究 Webhook 实现**：
```bash
# 启动 Tracee 发送 Webhook
sudo ./dist/tracee \
    --events execve \
    --webhook http://localhost:8080/tracee-events \
    --webhook-template '{"event":"{{.EventName}}","time":"{{.Timestamp}}"}'
```

2. **创建测试 Webhook 服务器** `test-webhook-server.go`：
```go
package main

import (
    "encoding/json"
    "fmt"
    "io"
    "log"
    "net/http"
)

type TraceeEvent struct {
    EventName string `json:"event"`
    Timestamp string `json:"time"`
    ProcessName string `json:"processName"`
    Args []interface{} `json:"args"`
}

func handleWebhook(w http.ResponseWriter, r *http.Request) {
    body, err := io.ReadAll(r.Body)
    if err != nil {
        http.Error(w, "Cannot read body", http.StatusBadRequest)
        return
    }

    var event TraceeEvent
    if err := json.Unmarshal(body, &event); err != nil {
        http.Error(w, "Invalid JSON", http.StatusBadRequest)
        return
    }

    // 处理事件
    fmt.Printf("Received event: %s from %s at %s\n",
        event.EventName, event.ProcessName, event.Timestamp)

    // 可以添加自定义逻辑
    // - 发送到 SIEM
    // - 触发告警
    // - 更新威胁情报数据库

    w.WriteHeader(http.StatusOK)
}

func main() {
    http.HandleFunc("/tracee-events", handleWebhook)
    log.Fatal(http.ListenAndServe(":8080", nil))
}
```

3. **实现 SIEM 集成**：
创建一个自定义 Sink，发送到 Elasticsearch：

`pkg/sinks/elasticsearch/elasticsearch.go`：
```go
package elasticsearch

import (
    "context"
    "encoding/json"

    "github.com/aquasecurity/tracee/types/protocol"
    "github.com/elastic/go-elasticsearch/v8"
)

type ElasticsearchSink struct {
    client *elasticsearch.Client
    index  string
}

func New(addresses []string, index string) (*ElasticsearchSink, error) {
    cfg := elasticsearch.Config{
        Addresses: addresses,
    }

    client, err := elasticsearch.NewClient(cfg)
    if err != nil {
        return nil, err
    }

    return &ElasticsearchSink{
        client: client,
        index:  index,
    }, nil
}

func (s *ElasticsearchSink) Write(event protocol.Event) error {
    data, err := json.Marshal(event)
    if err != nil {
        return err
    }

    _, err = s.client.Index(
        s.index,
        bytes.NewReader(data),
        s.client.Index.WithContext(context.Background()),
    )

    return err
}
```

4. **配置 Grafana 可视化**：
创建 Prometheus 指标导出：
```go
// pkg/metrics/prometheus.go 扩展
func (m *Metrics) RecordEvent(eventName string) {
    eventCounter.WithLabelValues(eventName).Inc()
}
```

5. **设计告警规则**：
创建 Prometheus 告警规则 `alerts.yml`：
```yaml
groups:
  - name: tracee-security-alerts
    interval: 30s
    rules:
      - alert: HighRateOfSuspiciousEvents
        expr: rate(tracee_events_total{type="suspicious"}[5m]) > 10
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "High rate of suspicious events detected"

      - alert: ContainerEscapeAttempt
        expr: increase(tracee_signatures_total{signature="container_escape"}[5m]) > 0
        for: 0m
        labels:
          severity: critical
        annotations:
          summary: "Container escape attempt detected"
```

**验证问题**：
- [ ] 如何保证 Webhook 的可靠性？
- [ ] 如何处理目标系统不可用？
- [ ] 如何实现事件批量发送？

**实战任务**：
设计一个完整的安全监控架构：
- Tracee → Kafka → Stream Processing → Elasticsearch
- Grafana 实时可视化
- AlertManager 告警通知
- 事件留存和回放功能

---

### 练习 5.4：CO-RE（一次编译，到处运行）

**目标**：理解 CO-RE 技术如何实现 eBPF 程序的可移植性

**涉及文件**：
- `pkg/ebpf/c/vmlinux.h` (内核类型定义)
- `pkg/ebpf/c/common/common.h` (CO-RE 帮助函数)
- `3rdparty/btf/` (BTF 文件)

**任务步骤**：

1. **理解 BTF（BPF Type Format）**：
```bash
# 检查系统 BTF 支持
ls /sys/kernel/btf/vmlinux

# 查看 BTF 信息
bpftool btf dump file /sys/kernel/btf/vmlinux | less

# 查看特定结构体
bpftool btf dump file /sys/kernel/btf/vmlinux format c | grep "struct task_struct"
```

2. **生成 vmlinux.h**：
```bash
# 使用 bpftool 生成当前内核的类型定义
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
```

3. **对比不同内核版本的结构体变化**：
```bash
# 下载不同版本内核的 BTF
# 比较 task_struct 在不同版本的差异
```

4. **编写 CO-RE 代码示例**：
```c
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>

SEC("kprobe/do_sys_openat2")
int BPF_KPROBE(kprobe__do_sys_openat2, int dfd, const char *filename)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    // CO-RE：自动处理字段偏移差异
    pid_t pid = BPF_CORE_READ(task, pid);
    pid_t tgid = BPF_CORE_READ(task, tgid);

    // CO-RE：处理字段存在性检查
    if (bpf_core_field_exists(task->mm)) {
        struct mm_struct *mm = BPF_CORE_READ(task, mm);
        // ...
    }

    return 0;
}
```

5. **理解 libbpf CO-RE 重定位**：
- 阅读 libbpf 文档
- 理解重定位类型（字段偏移、字段存在、类型大小等）
- 查看编译后的 BPF 对象文件中的重定位信息

```bash
# 查看重定位信息
llvm-objdump -r pkg/ebpf/c/tracee.bpf.o
```

6. **测试跨内核版本兼容性**：
```bash
# 在不同内核版本运行相同的 Tracee 二进制
# 验证 CO-RE 重定位是否正常工作
```

**验证问题**：
- [ ] 什么情况下 CO-RE 会失败？
- [ ] 如何处理内核不支持 BTF 的情况？
- [ ] CO-RE 的性能开销是多少？

**实战任务**：
编写一个 eBPF 程序，使用 CO-RE 特性：
- 读取 `task_struct` 的多个字段
- 处理字段在不同内核版本的差异
- 实现优雅的降级方案

---

## 第六阶段：生产部署（对应 Stage 6）

### 练习 6.1：Kubernetes 部署

**目标**：在 Kubernetes 集群中部署 Tracee

**涉及文件**：
- `deploy/kubernetes/` (K8s 配置)
- `deploy/helm/` (Helm Charts)

**任务步骤**：

1. **使用 Helm 部署**：
```bash
# 添加 Helm 仓库
helm repo add aqua https://aquasecurity.github.io/helm-charts/
helm repo update

# 查看可配置选项
helm show values aqua/tracee

# 部署
helm install tracee aqua/tracee \
    --namespace tracee-system \
    --create-namespace \
    --set hostPID=true
```

2. **自定义部署配置** `values.yaml`：
```yaml
# 自定义配置
config:
  # 只追踪容器
  scope: container

  # 启用特定事件
  events:
    - execve
    - openat
    - connect

  # 策略配置
  policies:
    - /config/policies/container-security.yaml

  # 输出配置
  output:
    format: json
    webhook:
      url: http://security-analytics-service.default.svc.cluster.local/events

# 资源限制
resources:
  limits:
    cpu: 1000m
    memory: 1Gi
  requests:
    cpu: 500m
    memory: 512Mi

# DaemonSet 配置（每个节点运行一个实例）
daemonset:
  enabled: true

# 权限配置
securityContext:
  privileged: true
  capabilities:
    add:
      - SYS_ADMIN
      - SYS_RESOURCE
      - NET_ADMIN
```

3. **创建安全策略 ConfigMap**：
```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: tracee-policies
  namespace: tracee-system
data:
  container-security.yaml: |
    apiVersion: tracee.aquasec.com/v1beta1
    kind: Policy
    metadata:
      name: k8s-container-security
    spec:
      scope:
        - container
        - not_comm=pause
      rules:
        - event: security_file_open
          filters:
            - data.pathname=/var/run/secrets/kubernetes.io/serviceaccount/*
        - event: ptrace
        - event: init_module
```

4. **监控和日志**：
```bash
# 查看 Tracee 日志
kubectl logs -n tracee-system -l app=tracee -f

# 查看资源使用
kubectl top pods -n tracee-system

# 查看事件（如果使用 Event 输出）
kubectl get events -n tracee-system
```

5. **故障排查**：
```bash
# 检查 Pod 状态
kubectl describe pod -n tracee-system -l app=tracee

# 进入 Pod 调试
kubectl exec -it -n tracee-system <pod-name> -- /bin/bash

# 检查 eBPF 程序
kubectl exec -it -n tracee-system <pod-name> -- bpftool prog list
```

**验证问题**：
- [ ] 如何确保 Tracee 可以访问宿主机内核？
- [ ] 如何处理节点内核版本不一致？
- [ ] 如何实现集中式日志收集？

**实战任务**：
设计一个生产级 Tracee 部署架构：
- 多集群支持
- 高可用输出（多个 Sink）
- 自动策略更新
- 告警集成（PagerDuty/Slack）

---

### 练习 6.2：性能调优和资源管理

**目标**：优化生产环境的 Tracee 性能和资源使用

**任务步骤**：

1. **基准测试**：
```bash
# 创建压力测试脚本
cat > stress-test.sh <<'EOF'
#!/bin/bash
# 生成各类事件
while true; do
    # 文件操作
    cat /etc/passwd > /dev/null
    ls -la / > /dev/null

    # 进程操作
    ps aux > /dev/null

    # 网络操作
    curl -s http://example.com > /dev/null

    sleep 0.1
done
EOF

# 运行压力测试
chmod +x stress-test.sh
./stress-test.sh &

# 监控 Tracee 性能
pidstat -p $(pidof tracee) 1
```

2. **调优参数**：
创建优化配置 `optimized-values.yaml`：
```yaml
config:
  # 减少追踪事件数量
  events:
    - execve
    - security_file_open

  # 使用高效的输出格式
  output:
    format: json

  # 启用事件聚合
  aggregate: true

  # Perf Buffer 大小
  perfBufferSize: 1024  # 页数

  # 批量处理
  batchSize: 100
  batchTimeout: 1s

resources:
  limits:
    cpu: 2000m
    memory: 2Gi
  requests:
    cpu: 1000m
    memory: 1Gi
```

3. **实施采样策略**：
```yaml
# 使用采样减少事件量
spec:
  scope:
    - container

  # 采样配置（每 10 个事件采样 1 个）
  sampling:
    rate: 0.1

  rules:
    - event: openat
      filters:
        # 只追踪特定路径
        - data.pathname=/etc/*
        - data.pathname=/var/*
```

4. **监控关键指标**：
创建 Grafana Dashboard 监控：
- 事件处理速率（events/s）
- CPU 使用率
- 内存使用
- 丢失事件数（Perf Buffer 溢出）
- eBPF Map 使用情况

5. **设置资源限制和 QoS**：
```yaml
# 使用 Guaranteed QoS
resources:
  limits:
    cpu: 1000m
    memory: 1Gi
  requests:
    cpu: 1000m  # 与 limits 相同
    memory: 1Gi

# 优先级
priorityClassName: system-node-critical
```

**验证问题**：
- [ ] 什么因素导致 Perf Buffer 溢出？
- [ ] 如何平衡事件覆盖率和性能？
- [ ] 资源限制过低会导致什么问题？

**实战任务**：
编写一个自动调优脚本：
- 监控事件丢失率
- 动态调整 Perf Buffer 大小
- 自动禁用高频事件
- 生成优化建议报告

---

### 练习 6.3：安全加固

**目标**：加固 Tracee 部署的安全性

**任务步骤**：

1. **最小权限原则**：
```yaml
# 使用 SecurityContext 限制权限
securityContext:
  # 必需的权限
  capabilities:
    add:
      - SYS_ADMIN      # 加载 eBPF 程序
      - SYS_RESOURCE   # 调整资源限制
      - NET_ADMIN      # 网络追踪
    drop:
      - ALL

  # 禁用特权模式（如果可能）
  privileged: false

  # 只读根文件系统
  readOnlyRootFilesystem: true

  # 非 root 用户（eBPF 需要 root，但可以尝试）
  runAsNonRoot: false
  runAsUser: 0
```

2. **网络策略**：
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: tracee-network-policy
  namespace: tracee-system
spec:
  podSelector:
    matchLabels:
      app: tracee

  policyTypes:
    - Egress

  egress:
    # 允许 DNS
    - to:
      - namespaceSelector: {}
      ports:
      - protocol: UDP
        port: 53

    # 允许访问 Webhook 服务
    - to:
      - podSelector:
          matchLabels:
            app: security-analytics
      ports:
      - protocol: TCP
        port: 8080

    # 允许访问 Kubernetes API（如果需要）
    - to:
      - namespaceSelector:
          matchLabels:
            name: default
      ports:
      - protocol: TCP
        port: 443
```

3. **Secret 管理**：
```yaml
# 使用 Secret 存储敏感配置
apiVersion: v1
kind: Secret
metadata:
  name: tracee-webhooks
  namespace: tracee-system
type: Opaque
stringData:
  webhook-url: "https://hooks.slack.com/services/XXX/YYY/ZZZ"
  webhook-token: "Bearer YOUR_TOKEN_HERE"

---
# 在 Deployment 中引用
spec:
  containers:
  - name: tracee
    env:
    - name: WEBHOOK_URL
      valueFrom:
        secretKeyRef:
          name: tracee-webhooks
          key: webhook-url
```

4. **审计日志**：
```yaml
# 记录 Tracee 自身的操作
config:
  # 启用审计日志
  auditLog:
    enabled: true
    path: /var/log/tracee/audit.log

  # 记录的操作
  auditEvents:
    - signature_loaded
    - policy_updated
    - probe_attached
    - probe_failed
```

5. **RBAC 配置**：
```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: tracee
  namespace: tracee-system

---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: tracee
rules:
  # 读取 Pod 信息（用于容器元数据）
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["get", "list", "watch"]

  # 读取 Namespace 信息
  - apiGroups: [""]
    resources: ["namespaces"]
    verbs: ["get", "list"]

  # 不需要写权限

---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: tracee
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: tracee
subjects:
  - kind: ServiceAccount
    name: tracee
    namespace: tracee-system
```

**验证问题**：
- [ ] Tracee 需要哪些最小权限才能工作？
- [ ] 如何防止 Tracee 被攻击者利用？
- [ ] 如何保护 Tracee 输出的敏感数据？

**实战任务**：
设计一个安全检查清单：
- 权限审计
- 网络隔离验证
- Secret 轮换策略
- 日志加密和留存
- 合规性检查（如 PCI-DSS、HIPAA）

---

## 🎯 进阶挑战项目

完成以上练习后，尝试这些综合项目：

### 项目 1：实时威胁检测平台

构建一个完整的威胁检测系统：

**功能**：
- Tracee 采集事件
- Kafka 消息队列
- Flink/Spark 实时分析
- 机器学习异常检测
- Grafana 可视化
- PagerDuty 告警

**技术挑战**：
- 处理高吞吐量事件流（10K+ events/s）
- 低延迟检测（< 1s）
- 误报率控制（< 1%）
- 跨主机攻击链关联

---

### 项目 2：容器逃逸检测引擎

开发专门检测容器逃逸的系统：

**检测技术**：
- OverlayFS 挂载检测
- Namespace 突破检测
- CGroup 限制绕过
- Docker socket 滥用
- Privileged 容器监控

**实现要求**：
- 10 个以上检测签名
- 完整的攻击路径重建
- 自动化响应（容器隔离/终止）
- 取证数据收集

---

### 项目 3：Tracee 扩展开发框架

创建一个插件系统，简化 Tracee 扩展：

**功能**：
- 插件 API 定义
- 热加载机制
- 配置管理
- 依赖管理
- 测试框架

**示例插件**：
- 威胁情报集成（VirusTotal, AlienVault）
- 自定义数据源
- 新的输出格式
- 事件聚合策略

---

## 📝 学习资源

### eBPF 学习
- [BPF Performance Tools](http://www.brendangregg.com/bpf-performance-tools-book.html)
- [Linux Observability with BPF](https://www.oreilly.com/library/view/linux-observability-with/9781492050193/)
- [libbpf Documentation](https://libbpf.readthedocs.io/)
- [eBPF.io](https://ebpf.io/)

### Linux 内核
- [Linux Kernel Development](https://www.kernel.org/doc/html/latest/)
- [Linux Tracing Technologies](https://www.kernel.org/doc/html/latest/trace/index.html)

### 安全
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Container Security Best Practices](https://kubernetes.io/docs/concepts/security/)

### Tracee 特定
- [Tracee Official Documentation](https://aquasecurity.github.io/tracee/)
- [Tracee GitHub Issues](https://github.com/aquasecurity/tracee/issues)
- [Aqua Security Blog](https://blog.aquasec.com/)

---

## 🎓 学习建议

1. **循序渐进**：不要跳过基础练习
2. **动手实践**：每个练习都要实际运行和修改代码
3. **阅读源码**：不要只看文档，深入理解实现
4. **写笔记**：记录你的发现和理解
5. **参与社区**：提问、贡献代码、分享经验
6. **保持好奇**：探索 Tracee 的每个角落

---

## ✅ 检查清单

跟踪你的学习进度：

### 第一阶段
- [ ] 练习 1.1：追踪第一个系统调用
- [ ] 练习 1.2：理解事件过滤机制
- [ ] 练习 1.3：探索输出格式

### 第二阶段
- [ ] 练习 2.1：理解 BPF Map 的使用
- [ ] 练习 2.2：追踪一个 Kprobe 的实现
- [ ] 练习 2.3：分析事件依赖关系

### 第三阶段
- [ ] 练习 3.1：容器识别机制
- [ ] 练习 3.2：复杂策略设计
- [ ] 练习 3.3：自定义数据源

### 第四阶段
- [ ] 练习 4.1：理解签名引擎架构
- [ ] 练习 4.2：编写 Go 签名
- [ ] 练习 4.3：Rego 签名开发

### 第五阶段
- [ ] 练习 5.1：性能分析与优化
- [ ] 练习 5.2：添加新事件
- [ ] 练习 5.3：集成外部系统
- [ ] 练习 5.4：CO-RE 技术

### 第六阶段
- [ ] 练习 6.1：Kubernetes 部署
- [ ] 练习 6.2：性能调优和资源管理
- [ ] 练习 6.3：安全加固

### 进阶项目
- [ ] 项目 1：实时威胁检测平台
- [ ] 项目 2：容器逃逸检测引擎
- [ ] 项目 3：Tracee 扩展开发框架

---

祝你学习愉快！如果遇到问题，欢迎参考其他学习文档或在 GitHub 提问。
