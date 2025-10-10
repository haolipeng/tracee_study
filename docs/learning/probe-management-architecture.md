# Tracee 探针管理架构详解

本文档详细介绍 Tracee 如何管理 150+ 个 eBPF 挂载点（探针）。

---

## 目录

- [1. 核心设计理念](#1-核心设计理念)
- [2. Handle 机制](#2-handle-机制)
- [3. ProbeGroup 管理器](#3-probegroup-管理器)
- [4. 探针接口设计](#4-探针接口设计)
- [5. 依赖管理系统](#5-依赖管理系统)
- [6. 兼容性检查机制](#6-兼容性检查机制)
- [7. Autoload 和延迟加载](#7-autoload-和延迟加载)
- [8. 完整生命周期](#8-完整生命周期)
- [9. 扩展机制](#9-扩展机制)

---

## 1. 核心设计理念

### 1.1 设计目标

Tracee 管理 150+ 探针的核心目标：

```
✅ 统一管理    - 所有探针通过统一接口管理
✅ 按需加载    - 只加载需要的探针，减少资源消耗
✅ 兼容性检查  - 自动检测探针是否与当前内核兼容
✅ 失败处理    - 优雅地处理探针加载失败
✅ 动态调整    - 运行时动态附加/分离探针
✅ 扩展性      - 支持第三方探针扩展
```

### 1.2 架构分层

```
┌──────────────────────────────────────────────────────────┐
│                  Event Layer (事件层)                     │
│  • 定义事件（execve, openat, etc）                        │
│  • 声明事件依赖的探针                                     │
└────────────────────┬─────────────────────────────────────┘
                     │
                     ▼
┌──────────────────────────────────────────────────────────┐
│            Dependency Manager (依赖管理层)                │
│  • 根据启用的事件确定需要的探针                           │
│  • 管理探针之间的依赖关系                                 │
│  • 处理探针失败和回退                                     │
└────────────────────┬─────────────────────────────────────┘
                     │
                     ▼
┌──────────────────────────────────────────────────────────┐
│              ProbeGroup (探针组管理层)                     │
│  • Handle → Probe 映射                                    │
│  • 统一的 Attach/Detach 接口                              │
│  • 线程安全的探针操作                                     │
└────────────────────┬─────────────────────────────────────┘
                     │
                     ▼
┌──────────────────────────────────────────────────────────┐
│                Probe Interface (探针接口层)               │
│  ┌────────────┬────────────┬──────────┬──────────────┐   │
│  │ TraceProbe │ LsmProbe   │ Uprobe   │ CgroupProbe  │   │
│  │ (kprobe/   │ (LSM Hook) │ (用户态) │ (CGroup SKB) │   │
│  │  tracepoint)│           │          │              │   │
│  └────────────┴────────────┴──────────┴──────────────┘   │
└────────────────────┬─────────────────────────────────────┘
                     │
                     ▼
┌──────────────────────────────────────────────────────────┐
│              libbpfgo / Kernel (内核层)                   │
│  • 实际的 eBPF 程序加载和附加                             │
└──────────────────────────────────────────────────────────┘
```

---

## 2. Handle 机制

### 2.1 什么是 Handle？

**Handle** 是探针的唯一标识符，使用整数枚举：

```go
// pkg/ebpf/probes/probes.go
type Handle int32

const (
    SysEnter Handle = iota       // 0
    SysExit                       // 1
    SyscallEnter__Internal        // 2
    SyscallExit__Internal         // 3
    SchedProcessFork              // 4
    SchedProcessExec              // 5
    // ... 150+ 个 Handle
)
```

### 2.2 Handle 的作用

```
1. 唯一标识
   每个探针有唯一的 Handle，避免字符串比较开销

2. 类型安全
   编译时检查，避免拼写错误

3. 快速查找
   使用 map[Handle]Probe 实现 O(1) 查找

4. 松耦合
   事件和探针通过 Handle 关联，而不是直接引用
```

### 2.3 Handle 命名规范

```go
// 系统调用相关
SysEnter, SysExit

// 调度器相关
SchedProcessFork, SchedProcessExec, SchedProcessExit

// 安全钩子
SecurityFileOpen, SecuritySocketConnect

// VFS 操作
VfsWrite, VfsWriteRet  // Ret 后缀表示 kretprobe

// 特殊用途
SignalCgroupMkdir      // Signal 前缀表示信号事件
```

---

## 3. ProbeGroup 管理器

### 3.1 ProbeGroup 结构

```go
// pkg/ebpf/probes/probe_group.go
type ProbeGroup struct {
    probesLock *sync.Mutex     // 互斥锁，保证线程安全
    module     *bpf.Module     // libbpfgo eBPF 模块
    probes     map[Handle]Probe // Handle → Probe 映射表
}
```

**核心特点**：
- ✅ 线程安全（所有操作都有锁保护）
- ✅ 统一管理所有探针
- ✅ 提供统一的操作接口

### 3.2 初始化流程

```go
// pkg/ebpf/probes/probe_group.go:185
func NewDefaultProbeGroup(
    module *bpf.Module,
    netEnabled bool,
    defaultAutoload bool,
) (*ProbeGroup, error) {
    binaryPath := "/proc/self/exe"

    // 定义所有探针
    allProbes := map[Handle]Probe{
        // Raw Tracepoints
        SysEnter: NewTraceProbe(
            RawTracepoint,
            "raw_syscalls:sys_enter",  // 事件名
            "trace_sys_enter",          // eBPF 程序名
        ),

        SchedProcessFork: NewTraceProbe(
            RawTracepoint,
            "sched:sched_process_fork",
            "tracepoint__sched__sched_process_fork",
        ),

        // Kprobes
        SecurityFileOpen: NewTraceProbe(
            KProbe,
            "security_file_open",      // 内核函数名
            "trace_security_file_open", // eBPF 程序名
        ),

        // Kretprobes
        VfsWriteRet: NewTraceProbe(
            KretProbe,
            "vfs_write",
            "trace_ret_vfs_write",
        ),

        // Uprobes
        SyscallTableCheck: NewFixedUprobe(
            Uprobe,
            "uprobe_syscall_table_check",
            binaryPath,  // Tracee 自己的二进制
            UprobeEventSymbol("github.com/aquasecurity/tracee/pkg/ebpf.(*Tracee).triggerSyscallTableIntegrityCheckCall"),
        ),

        // CGroup SKB
        CgroupSKBIngress: NewCgroupProbe(
            bpf.BPFAttachTypeCgroupInetIngress,
            "cgroup_skb_ingress",
        ),

        // LSM Hook
        LsmFileOpen: NewLsmProgramProbe(
            "file_open",
            "lsm_file_open",
        ),

        // ... 150+ 个探针定义
    }

    // 添加扩展探针（第三方插件）
    extensionProbes := getExtensionProbeGroup()
    for handle, probe := range extensionProbes {
        if _, exists := allProbes[handle]; exists {
            logger.Errorw("probe handle already exists", "handle", handle)
            continue
        }
        allProbes[handle] = probe
    }

    // 根据配置禁用某些探针
    if !netEnabled {
        // 禁用网络探针（避免需要 CAP_NET_ADMIN）
        allProbes[CgroupSKBIngress].autoload(module, false)
        allProbes[CgroupSKBEgress].autoload(module, false)
    }

    if !defaultAutoload {
        // 禁用所有探针的自动加载
        for handle := range allProbes {
            allProbes[handle].autoload(module, false)
        }
    }

    return NewProbeGroup(module, allProbes), nil
}
```

### 3.3 核心操作

#### 附加探针

```go
// pkg/ebpf/probes/probe_group.go:128
func (p *ProbeGroup) Attach(handle Handle, args ...interface{}) error {
    p.probesLock.Lock()
    defer p.probesLock.Unlock()

    if _, ok := p.probes[handle]; !ok {
        return errfmt.Errorf("probe handle (%d) does not exist", handle)
    }

    // 调用具体探针的 attach 方法
    return p.probes[handle].attach(p.module, args...)
}
```

#### 分离探针

```go
// pkg/ebpf/probes/probe_group.go:140
func (p *ProbeGroup) Detach(handle Handle, args ...interface{}) error {
    p.probesLock.Lock()
    defer p.probesLock.Unlock()

    if _, ok := p.probes[handle]; !ok {
        return errfmt.Errorf("probe handle (%d) does not exist", handle)
    }

    return p.probes[handle].detach(args...)
}
```

#### 分离所有探针

```go
// pkg/ebpf/probes/probe_group.go:152
func (p *ProbeGroup) DetachAll() error {
    p.probesLock.Lock()
    defer p.probesLock.Unlock()

    for _, pr := range p.probes {
        err := pr.detach()
        if err != nil {
            return errfmt.WrapError(err)
        }
    }

    return nil
}
```

#### 兼容性检查

```go
// pkg/ebpf/probes/probe_group.go:116
func (p *ProbeGroup) IsProbeCompatible(handle Handle, env EnvironmentProvider) (bool, error) {
    p.probesLock.Lock()
    defer p.probesLock.Unlock()

    if probe, ok := p.probes[handle]; ok {
        return probe.isCompatible(env)
    }

    return false, errfmt.Errorf("probe handle (%d) does not exist", handle)
}
```

---

## 4. 探针接口设计

### 4.1 Probe 接口

所有探针都实现统一的接口：

```go
// pkg/ebpf/probes/probes.go:10
type Probe interface {
    // attach 附加探针到内核钩子
    attach(module *bpf.Module, args ...interface{}) error

    // detach 从内核钩子分离探针
    detach(...interface{}) error

    // autoload 设置 eBPF 程序是否自动加载
    autoload(module *bpf.Module, autoload bool) error

    // isCompatible 检查探针是否与当前环境兼容
    isCompatible(env EnvironmentProvider) (bool, error)
}
```

### 4.2 TraceProbe 实现

**TraceProbe** 支持 kprobe、kretprobe、tracepoint、raw tracepoint：

```go
// pkg/ebpf/probes/trace.go:66
type TraceProbe struct {
    ProbeCompatibility        // 兼容性检查
    eventName   string        // 事件名称（如 "sys_enter"）
    programName string        // eBPF 程序名称
    probeType   ProbeType     // 探针类型（KProbe/RawTracepoint 等）
    bpfLink     []*bpf.BPFLink // BPF 链接（可能有多个地址）
    attached    bool          // 是否已附加
}

func (p *TraceProbe) attach(module *bpf.Module, args ...interface{}) error {
    if p.attached {
        return nil // 已附加，幂等操作
    }

    prog, err := module.GetProgram(p.programName)
    if err != nil {
        return errfmt.WrapError(err)
    }

    switch p.probeType {
    case KProbe:
        // 附加 kprobe
        link, err := prog.AttachKprobe(p.eventName)
        if err != nil {
            return errfmt.WrapError(err)
        }
        p.bpfLink = append(p.bpfLink, link)

    case KretProbe:
        // 附加 kretprobe
        link, err := prog.AttachKretprobe(p.eventName)
        if err != nil {
            return errfmt.WrapError(err)
        }
        p.bpfLink = append(p.bpfLink, link)

    case RawTracepoint:
        // 附加 raw tracepoint
        link, err := prog.AttachRawTracepoint(p.eventName)
        if err != nil {
            return errfmt.WrapError(err)
        }
        p.bpfLink = append(p.bpfLink, link)

    case Tracepoint:
        // 附加传统 tracepoint
        parts := strings.Split(p.eventName, ":")
        link, err := prog.AttachTracepoint(parts[0], parts[1])
        if err != nil {
            return errfmt.WrapError(err)
        }
        p.bpfLink = append(p.bpfLink, link)

    default:
        return errfmt.Errorf("unsupported probe type: %d", p.probeType)
    }

    p.attached = true
    return nil
}
```

### 4.3 LsmProgramProbe 实现

```go
// pkg/ebpf/probes/lsm.go:14
type LsmProgramProbe struct {
    ProbeCompatibility
    hookName    string
    programName string
    bpfLink     *bpf.BPFLink
    attached    bool
}

func (p *LsmProgramProbe) attach(module *bpf.Module, args ...interface{}) error {
    if p.attached {
        return nil
    }

    prog, err := module.GetProgram(p.programName)
    if err != nil {
        return errfmt.WrapError(err)
    }

    // 附加 LSM Hook
    link, err := prog.AttachLSM()
    if err != nil {
        return errfmt.WrapError(err)
    }

    p.bpfLink = link
    p.attached = true
    return nil
}
```

### 4.4 UprobeProbe 实现

```go
// pkg/ebpf/probes/uprobe.go
type UprobeProbe struct {
    ProbeCompatibility
    programName string
    binaryPath  string
    symbol      string
    offset      uint32
    bpfLink     *bpf.BPFLink
    attached    bool
}

func (p *UprobeProbe) attach(module *bpf.Module, args ...interface{}) error {
    if p.attached {
        return nil
    }

    prog, err := module.GetProgram(p.programName)
    if err != nil {
        return errfmt.WrapError(err)
    }

    // 附加 uprobe 到用户态二进制
    link, err := prog.AttachUprobe(
        -1,              // PID (-1 表示所有进程，但这里是 self)
        p.binaryPath,    // 二进制路径
        p.offset,        // 偏移量
    )
    if err != nil {
        return errfmt.WrapError(err)
    }

    p.bpfLink = link
    p.attached = true
    return nil
}
```

### 4.5 CgroupProbe 实现

```go
// pkg/ebpf/probes/cgroup.go
type CgroupProbe struct {
    ProbeCompatibility
    attachType  bpf.BPFAttachType  // Ingress/Egress
    programName string
    bpfLink     *bpf.BPFLink
    attached    bool
}

func (p *CgroupProbe) attach(module *bpf.Module, args ...interface{}) error {
    if p.attached {
        return nil
    }

    // 从参数获取 cgroup
    cgroups, ok := args[0].(*cgroup.Cgroups)
    if !ok {
        return errfmt.Errorf("invalid cgroup argument")
    }

    prog, err := module.GetProgram(p.programName)
    if err != nil {
        return errfmt.WrapError(err)
    }

    // 附加到 cgroup
    cgroupPath := cgroups.GetDefaultCgroup().GetMountPoint()
    link, err := prog.AttachCgroup(cgroupPath)
    if err != nil {
        return errfmt.WrapError(err)
    }

    p.bpfLink = link
    p.attached = true
    return nil
}
```

---

## 5. 依赖管理系统

### 5.1 事件和探针的依赖关系

Tracee 使用 **依赖管理器** 来管理事件和探针之间的关系：

```
Event (execve)
    ↓ depends on
Probe (SchedProcessExec)
    ↓ fallback to
Probe (SecurityBPRMCheck)
```

### 5.2 依赖管理器订阅机制

```go
// pkg/ebpf/tracee.go:1352
func (t *Tracee) attachProbes() error {
    // 订阅探针添加事件
    t.eventsDependencies.SubscribeAdd(
        dependencies.ProbeNodeType,
        func(node interface{}) []dependencies.Action {
            probeNode, ok := node.(*dependencies.ProbeNode)
            if !ok {
                logger.Errorw("Got node from type not requested")
                return nil
            }

            // 附加探针
            err := t.defaultProbes.Attach(
                probeNode.GetHandle(),
                t.cgroups,
                t.getKernelSymbols(),
            )
            if err != nil {
                // 取消添加
                return []dependencies.Action{
                    dependencies.NewCancelNodeAddAction(err),
                }
            }
            return nil
        })

    // 订阅探针移除事件
    t.eventsDependencies.SubscribeRemove(
        dependencies.ProbeNodeType,
        func(node interface{}) []dependencies.Action {
            probeNode, ok := node.(*dependencies.ProbeNode)
            if !ok {
                logger.Errorw("Got node from type not requested")
                return nil
            }

            // 分离探针
            err := t.defaultProbes.Detach(probeNode.GetHandle())
            if err != nil {
                logger.Debugw("Failed to detach probe",
                    "probe", probeNode.GetHandle(),
                    "error", err)
            }
            return nil
        })

    // 附加所有当前需要的探针
    for _, probeHandle := range t.eventsDependencies.GetProbes() {
        err := t.defaultProbes.Attach(
            probeHandle,
            t.cgroups,
            t.getKernelSymbols(),
        )
        if err != nil {
            // 标记探针失败
            failErr := t.eventsDependencies.FailProbe(probeHandle)
            if failErr != nil {
                logger.Warnw("Failed to fail probe",
                    "probe", probeHandle,
                    "error", failErr)
            }
        }
    }

    return nil
}
```

### 5.3 动态探针管理

```
用户启用事件 (execve)
    ↓
依赖管理器确定需要探针 (SchedProcessExec)
    ↓
触发 SubscribeAdd 回调
    ↓
ProbeGroup.Attach(SchedProcessExec)
    ↓
探针附加到内核

用户禁用事件 (execve)
    ↓
依赖管理器确定不再需要探针
    ↓
触发 SubscribeRemove 回调
    ↓
ProbeGroup.Detach(SchedProcessExec)
    ↓
探针从内核分离
```

---

## 6. 兼容性检查机制

### 6.1 兼容性要求系统

```go
// pkg/ebpf/probes/compatibility.go
type CompatibilityRequirement interface {
    Check(env EnvironmentProvider) (bool, error)
}

type ProbeCompatibility struct {
    requirements []CompatibilityRequirement
}

func (p *ProbeCompatibility) isCompatible(env EnvironmentProvider) (bool, error) {
    for _, req := range p.requirements {
        compatible, err := req.Check(env)
        if err != nil || !compatible {
            return false, err
        }
    }
    return true, nil
}
```

### 6.2 内核版本要求

```go
type KernelVersionRequirement struct {
    minVersion string // 最小版本（如 "5.7.0"）
    maxVersion string // 最大版本（可选）
}

func (r *KernelVersionRequirement) Check(env EnvironmentProvider) (bool, error) {
    currentVersion := env.GetOSInfo().GetKernelRelease()

    // 比较版本
    if r.minVersion != "" {
        if !versionGreaterOrEqual(currentVersion, r.minVersion) {
            return false, nil
        }
    }

    if r.maxVersion != "" {
        if !versionLessOrEqual(currentVersion, r.maxVersion) {
            return false, nil
        }
    }

    return true, nil
}
```

### 6.3 BPF 程序类型要求

```go
type BpfProgramRequirement struct {
    progType bpf.BPFProgType // 如 BPF_PROG_TYPE_LSM
}

func (r *BpfProgramRequirement) Check(env EnvironmentProvider) (bool, error) {
    // 检查内核是否支持该 BPF 程序类型
    return checkBpfProgTypeSupported(r.progType)
}
```

### 6.4 兼容性检查流程

```go
// pkg/ebpf/tracee.go:1408
func (t *Tracee) validateProbesCompatibility() error {
    // 订阅新探针的兼容性检查
    t.eventsDependencies.SubscribeAdd(
        dependencies.ProbeNodeType,
        func(node interface{}) []dependencies.Action {
            probeNode, ok := node.(*dependencies.ProbeNode)
            if !ok {
                logger.Errorw("Got node from type not requested")
                return nil
            }

            // 检查兼容性
            compatible, err := t.defaultProbes.IsProbeCompatible(
                probeNode.GetHandle(),
                t.config.OSInfo,
            )
            if err != nil {
                logger.Warnw("Failed to check probe compatibility", "error", err)
                return nil
            }

            if !compatible {
                // 探针不兼容，标记失败
                return []dependencies.Action{
                    dependencies.NewFailNodeAddAction(
                        errors.New("probe is not compatible"),
                    ),
                }
            }

            return nil
        })

    // 检查现有探针
    for _, probeHandle := range t.eventsDependencies.GetProbes() {
        compatible, err := t.defaultProbes.IsProbeCompatible(
            probeHandle,
            t.config.OSInfo,
        )
        if err != nil {
            logger.Errorw("Failed to check compatibility", "error", err)
            continue
        }

        if !compatible {
            logger.Debugw("Probe incompatible", "probe", probeHandle)
            err := t.eventsDependencies.FailProbe(probeHandle)
            if err != nil {
                logger.Warnw("Failed to fail probe", "error", err)
            }
        }
    }

    return nil
}
```

### 6.5 回退机制示例

```go
// 事件定义中指定主探针和回退探针
Event{
    Name: "file_open",
    Dependencies: []Dependency{
        {
            // 主探针：LSM Hook（需要内核 5.7+）
            Probe: probes.LsmFileOpen,
            Fallback: []Dependency{
                {
                    // 回退探针：Kprobe（兼容性更好）
                    Probe: probes.SecurityFileOpen,
                },
            },
        },
    },
}
```

工作流程：
```
1. 尝试附加 LsmFileOpen
   ↓
2. 检查兼容性（需要 5.7+）
   ↓
3. 如果不兼容，标记失败
   ↓
4. 依赖管理器自动尝试 SecurityFileOpen
   ↓
5. SecurityFileOpen 兼容性检查通过
   ↓
6. 附加 SecurityFileOpen
```

---

## 7. Autoload 和延迟加载

### 7.1 什么是 Autoload？

在 libbpfgo 中，**autoload** 指 eBPF 程序是否在对象加载时自动加载到内核。

```
autoload = true  (默认)
  ↓
BPFLoadObject() 时自动加载所有程序到内核
  ↓
即使不需要也会占用内核资源

autoload = false
  ↓
BPFLoadObject() 时跳过此程序
  ↓
需要时再手动加载
```

### 7.2 Tracee 的 Autoload 策略

```go
// pkg/ebpf/probes/probe_group.go:364
if !defaultAutoload {
    // 禁用所有探针的自动加载
    for handle := range allProbes {
        if err := allProbes[handle].autoload(module, false); err != nil {
            logger.Errorw("Failed to disable autoload",
                "handle", handle,
                "error", err)
        }
    }
}
```

**优点**：
- ✅ 按需加载，减少内存占用
- ✅ 减少加载时间
- ✅ 避免加载不需要的探针

**流程**：
```
1. 初始化时禁用所有探针的 autoload
   ↓
2. BPFLoadObject() 只加载 eBPF 程序元数据，不加载程序本身
   ↓
3. 用户启用事件时
   ↓
4. 依赖管理器确定需要的探针
   ↓
5. 调用 Attach() 时才真正加载程序到内核
```

### 7.3 Autoload 实现

```go
// pkg/ebpf/probes/trace.go
func (p *TraceProbe) autoload(module *bpf.Module, autoload bool) error {
    prog, err := module.GetProgram(p.programName)
    if err != nil {
        return errfmt.WrapError(err)
    }

    // 设置程序的 autoload 属性
    return prog.SetAutoload(autoload)
}
```

---

## 8. 完整生命周期

### 8.1 启动流程

```
1. main()
   ↓
2. Tracee.Init()
   ↓
3. initBPFProbes()
   ├─ NewModuleFromBuffer()      // 打开 eBPF 对象文件
   ├─ NewDefaultProbeGroup()      // 创建 150+ 探针定义
   └─ validateProbesCompatibility() // 检查兼容性
   ↓
4. initBPF()
   ├─ setProgramsAutoload()       // 根据事件设置 autoload
   ├─ BPFLoadObject()             // 加载 eBPF 对象到内核
   └─ populateBPFMaps()           // 填充 eBPF maps
   ↓
5. attachProbes()
   ├─ 订阅依赖管理器事件
   ├─ 遍历所有需要的探针
   └─ ProbeGroup.Attach()         // 附加探针到内核
   ↓
6. Start()
   └─ 开始处理事件
```

### 8.2 运行时动态调整

```
用户通过 API 启用新事件
   ↓
Tracee 更新事件状态
   ↓
依赖管理器检测到变化
   ↓
触发 SubscribeAdd 回调
   ↓
检查新探针兼容性
   ↓
如果兼容，调用 Attach()
   ↓
探针附加到内核
   ↓
事件开始产生
```

### 8.3 关闭流程

```
1. Tracee.Close()
   ↓
2. ProbeGroup.DetachAll()
   ├─ 遍历所有探针
   └─ 调用每个探针的 detach()
       ↓
       各探针分离：
       ├─ TraceProbe: link.Destroy()
       ├─ LsmProbe: link.Destroy()
       ├─ UprobeProbe: link.Destroy()
       └─ CgroupProbe: link.Destroy()
   ↓
3. bpfModule.Close()
   └─ 关闭 eBPF 对象，释放资源
```

---

## 9. 扩展机制

### 9.1 扩展探针注册

Tracee 支持第三方扩展注册自定义探针：

```go
// pkg/ebpf/probes/probe_group.go:22
func RegisterExtensionProbeGroup(probes map[Handle]Probe) error {
    extensionProbeGroupMu.Lock()
    defer extensionProbeGroupMu.Unlock()

    // 验证所有探针
    for handle, probe := range probes {
        if probe == nil {
            return errfmt.Errorf("probe cannot be nil")
        }
        if _, exists := extensionProbeGroup[handle]; exists {
            return errfmt.Errorf("probe handle %d already exists", handle)
        }
    }

    // 添加到扩展探针组
    for handle, probe := range probes {
        extensionProbeGroup[handle] = probe
    }

    return nil
}
```

### 9.2 扩展探针使用示例

```go
// 第三方扩展
package myextension

import "github.com/aquasecurity/tracee/pkg/ebpf/probes"

const (
    // 自定义 Handle（使用大于 1000 的值避免冲突）
    MyCustomProbe probes.Handle = 10000
)

func init() {
    // 注册自定义探针
    customProbes := map[probes.Handle]probes.Probe{
        MyCustomProbe: probes.NewTraceProbe(
            probes.KProbe,
            "my_custom_kernel_function",
            "trace_my_custom_function",
        ),
    }

    err := probes.RegisterExtensionProbeGroup(customProbes)
    if err != nil {
        panic(err)
    }
}
```

### 9.3 扩展探针集成

```go
// pkg/ebpf/probes/probe_group.go:341
// 在 NewDefaultProbeGroup 中自动集成
extensionProbeGroup := getExtensionProbeGroup()
for handle, extProbes := range extensionProbeGroup {
    if _, exists := allProbes[handle]; exists {
        logger.Errorw("probe handle already exists", "handle", handle)
        continue
    }
    allProbes[handle] = extProbes
}
```

---

## 10. 总结

### 10.1 管理策略总结

| 方面 | 策略 | 优势 |
|-----|------|------|
| **组织方式** | Handle + map[Handle]Probe | O(1) 查找、类型安全 |
| **加载方式** | 延迟加载（autoload=false） | 节省资源、按需加载 |
| **兼容性** | 声明式要求 + 运行时检查 | 自动回退、优雅降级 |
| **线程安全** | 互斥锁保护 | 支持并发操作 |
| **扩展性** | 注册机制 | 支持第三方扩展 |
| **依赖管理** | 订阅机制 + 自动附加/分离 | 动态调整、资源优化 |

### 10.2 关键设计模式

#### 1. **统一接口模式**
```
所有探针实现 Probe 接口
→ 统一管理、易于扩展
```

#### 2. **Handle 模式**
```
使用整数 Handle 而非字符串
→ 类型安全、高性能
```

#### 3. **延迟加载模式**
```
默认禁用 autoload，需要时才加载
→ 减少资源消耗
```

#### 4. **订阅者模式**
```
依赖管理器通知探针状态变化
→ 解耦、灵活
```

#### 5. **策略模式**
```
不同探针类型（TraceProbe, LsmProbe 等）
→ 封装差异、统一接口
```

#### 6. **回退模式**
```
主探针失败时自动尝试回退探针
→ 提高兼容性
```

### 10.3 性能优化技巧

```
1. 按需加载
   只加载需要的探针，而不是全部 150+

2. 探针复用
   多个事件可以共享同一个探针

3. 幂等操作
   Attach() 可以多次调用，已附加的不重复操作

4. 线程安全
   使用互斥锁而非读写锁（探针操作通常是写操作）

5. 批量操作
   提供 DetachAll() 等批量接口
```

### 10.4 未来改进方向

```
1. 探针池化
   重用探针对象，减少内存分配

2. 更智能的回退
   基于性能和兼容性自动选择最优探针

3. 热更新
   支持不重启的探针更新

4. 探针统计
   收集探针性能数据，优化选择策略

5. LSM 迁移
   更多 kprobe 迁移到 LSM Hook
```

---

## 参考资料

- [ProbeGroup 源代码](../../../pkg/ebpf/probes/probe_group.go)
- [Probe 接口定义](../../../pkg/ebpf/probes/probes.go)
- [兼容性检查](../../../pkg/ebpf/probes/compatibility.go)
- [依赖管理系统](../../../pkg/ebpf/dependencies/)
- [libbpfgo 文档](https://github.com/aquasecurity/libbpfgo)

---

**相关文档：**
- [eBPF 挂载点分类](./ebpf-probe-types.md)
- [架构概览](./01-architecture-overview.md)
- [eBPF 实现详解](./03-ebpf-implementation.md)
