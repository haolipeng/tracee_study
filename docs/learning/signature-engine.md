# Tracee 签名引擎深度解析

> 预估学习时长：3-4 天 | 难度：高级 (4/5)

## 目录

1. [概述与学习目标](#1-概述与学习目标)
2. [签名引擎架构图](#2-签名引擎架构图)
3. [核心接口定义](#3-核心接口定义)
4. [签名类型对比](#4-签名类型对比go-签名-vs-rego-签名)
5. [SignaturesEngine 实现详解](#5-signaturesengine-实现详解)
6. [签名生命周期](#6-签名生命周期)
7. [内置签名分析](#7-内置签名分析)
8. [自定义签名开发完整指南](#8-自定义签名开发完整指南)
9. [动手练习](#9-动手练习)
10. [核心代码走读](#10-核心代码走读)

---

## 1. 概述与学习目标

### 1.1 什么是签名引擎

Tracee 的签名引擎 (Signatures Engine) 是一个强大的规则检测系统，它能够：

- **实时检测安全威胁**：分析来自 eBPF 的系统事件，识别恶意行为
- **可扩展的规则系统**：支持 Go 语言和 Rego 语言编写检测规则
- **MITRE ATT&CK 映射**：内置签名与 ATT&CK 框架对齐
- **插件化架构**：支持动态加载外部签名

### 1.2 学习目标

完成本教程后，你将能够：

1. **理解架构**：掌握签名引擎的整体设计和核心组件
2. **掌握接口**：深入理解 `Signature`、`Finding`、`SignatureEventSelector` 等核心接口
3. **分析源码**：能够阅读和理解 Tracee 内置签名的实现
4. **开发签名**：独立开发自定义安全检测签名
5. **调试优化**：能够调试签名并优化性能

### 1.3 前置知识

- Go 语言基础（接口、并发、通道）
- Linux 系统调用基础
- 基本的安全概念（恶意软件行为、攻击技术）

---

## 2. 签名引擎架构图

### 2.1 整体架构

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           Tracee Signatures Engine                          │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌──────────────┐    ┌──────────────────────────────────────────────────┐  │
│  │  Event       │    │              Signatures Engine                    │  │
│  │  Sources     │    │  ┌─────────────────────────────────────────────┐ │  │
│  │              │    │  │            Signature Index                   │ │  │
│  │ ┌──────────┐ │    │  │  ┌───────────────┐  ┌───────────────────┐  │ │  │
│  │ │  Tracee  │─┼───►│  │  │ EventSelector │──│ []Signature       │  │ │  │
│  │ │  Events  │ │    │  │  │ {Source,Name, │  │ [sig1,sig2,sig3]  │  │ │  │
│  │ │ (eBPF)   │ │    │  │  │  Origin}      │  │                   │  │ │  │
│  │ └──────────┘ │    │  │  └───────────────┘  └───────────────────┘  │ │  │
│  │              │    │  └─────────────────────────────────────────────┘ │  │
│  │ protocol.    │    │                        │                          │  │
│  │ Event        │    │                        ▼                          │  │
│  │              │    │  ┌─────────────────────────────────────────────┐ │  │
│  └──────────────┘    │  │           Dispatch & Match                   │ │  │
│                      │  │                                               │ │  │
│                      │  │  for each matching signature:                 │ │  │
│                      │  │    signature.OnEvent(event)                   │ │  │
│                      │  │                                               │ │  │
│                      │  └─────────────────────────────────────────────┘ │  │
│                      │                        │                          │  │
│                      │                        ▼                          │  │
│                      │  ┌─────────────────────────────────────────────┐ │  │
│                      │  │           Callback Handler                   │ │  │
│                      │  │                                               │ │  │
│                      │  │  sig.cb(&detect.Finding{                      │ │  │
│                      │  │      SigMetadata: metadata,                   │ │  │
│                      │  │      Event: event,                            │ │  │
│                      │  │      Data: additionalData,                    │ │  │
│                      │  │  })                                           │ │  │
│                      │  └─────────────────────────────────────────────┘ │  │
│                      └──────────────────────────────────────────────────┘  │
│                                              │                              │
│                                              ▼                              │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │                        Output Channel                                 │  │
│  │                    chan *detect.Finding                               │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
│                                              │                              │
│                                              ▼                              │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │   Output Sinks: JSON, Webhook, Syslog, Prometheus, GRPC...           │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 2.2 核心数据流

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   eBPF      │     │  Protocol   │     │  Signature  │     │   Finding   │
│   Event     │────►│   Event     │────►│   Match     │────►│   Output    │
│             │     │             │     │             │     │             │
└─────────────┘     └─────────────┘     └─────────────┘     └─────────────┘
      │                   │                   │                   │
      ▼                   ▼                   ▼                   ▼
 trace.Event         protocol.Event      Signature.         detect.Finding
 (内核事件)          (通用事件封装)       OnEvent()          (检测结果)
```

### 2.3 签名索引结构

```
SignaturesIndex Map:
┌────────────────────────────────────────────────────────────────┐
│ Key: SignatureEventSelector          Value: []Signature       │
├────────────────────────────────────────────────────────────────┤
│ {Source:"tracee", Name:"ptrace",     [AntiDebugging,          │
│  Origin:"*"}                          PtraceInjection]         │
├────────────────────────────────────────────────────────────────┤
│ {Source:"tracee", Name:"execve",     [FilelessExec,           │
│  Origin:"container"}                  SuspiciousExec]          │
├────────────────────────────────────────────────────────────────┤
│ {Source:"tracee", Name:"*",          [GenericMonitor]         │
│  Origin:"*"}                                                   │
└────────────────────────────────────────────────────────────────┘
```

---

## 3. 核心接口定义

### 3.1 Signature 接口

`Signature` 是签名引擎的基本业务逻辑单元，定义在 `types/detect/detect.go`：

```go
// Signature 是规则引擎的基本业务逻辑单元
type Signature interface {
    // GetMetadata 允许签名声明关于自身的信息
    GetMetadata() (SignatureMetadata, error)

    // GetSelectedEvents 允许签名声明它订阅的事件
    GetSelectedEvents() ([]SignatureEventSelector, error)

    // Init 允许签名初始化其内部状态
    Init(ctx SignatureContext) error

    // Close 在 Init 操作后清理签名
    Close()

    // OnEvent 允许签名处理引擎传递的事件，这是签名的业务逻辑
    OnEvent(event protocol.Event) error

    // OnSignal 允许签名处理签名的生命周期事件
    OnSignal(signal Signal) error
}
```

**接口方法详解：**

| 方法 | 用途 | 调用时机 |
|------|------|----------|
| `GetMetadata()` | 返回签名元信息（ID、名称、描述等） | 加载时、输出时 |
| `GetSelectedEvents()` | 声明订阅的事件类型 | 加载时建立索引 |
| `Init(ctx)` | 初始化内部状态，保存回调函数 | 签名加载后 |
| `Close()` | 清理资源 | 签名卸载时 |
| `OnEvent(event)` | 核心检测逻辑 | 每个匹配事件到达时 |
| `OnSignal(signal)` | 处理生命周期信号 | 数据源结束等 |

### 3.2 SignatureMetadata 结构

```go
// SignatureMetadata 表示关于签名的信息
type SignatureMetadata struct {
    ID          string                 // 唯一标识符，如 "TRC-102"
    Version     string                 // 版本号
    Name        string                 // 人类可读名称
    EventName   string                 // 生成的事件名称
    Description string                 // 详细描述
    Tags        []string               // 标签列表
    Properties  map[string]interface{} // 额外属性（严重性、MITRE映射等）
}
```

**Properties 常用字段：**

```go
Properties: map[string]interface{}{
    "Severity":             3,                    // 严重性 1-3
    "Category":             "defense-evasion",    // MITRE 战术类别
    "Technique":            "Rootkit",            // MITRE 技术
    "Kubernetes_Technique": "",                   // K8s 特定技术
    "id":                   "attack-pattern--...", // STIX ID
    "external_id":          "T1014",              // MITRE ID
}
```

### 3.3 SignatureEventSelector 结构

```go
// SignatureEventSelector 表示签名订阅的事件
type SignatureEventSelector struct {
    Source string  // 事件来源，如 "tracee"
    Name   string  // 事件名称，如 "ptrace"，"*" 表示所有
    Origin string  // 事件起源，"host"/"container"/"*"
}
```

**Selector 匹配规则：**

```go
// 精确匹配
{Source: "tracee", Name: "execve", Origin: "container"}

// 通配符匹配所有事件名
{Source: "tracee", Name: "*", Origin: "host"}

// 通配符匹配所有来源
{Source: "tracee", Name: "ptrace", Origin: "*"}

// 双通配符
{Source: "tracee", Name: "*", Origin: "*"}
```

### 3.4 SignatureContext 结构

```go
type SignatureContext struct {
    Callback      SignatureHandler                              // 报告检测结果的回调
    Logger        Logger                                         // 日志接口
    GetDataSource func(namespace string, id string) (DataSource, bool) // 数据源访问
}

// SignatureHandler 是报告发现的回调函数
type SignatureHandler func(found *Finding)
```

### 3.5 Finding 结构

```go
// Finding 是签名的主要输出，表示签名业务逻辑的匹配结果
type Finding struct {
    dataLock    sync.RWMutex           // 并发安全锁
    Data        map[string]interface{} // 关于发现上下文的有用信息
    Event       protocol.Event         // 触发发现的事件
    SigMetadata SignatureMetadata      // 签名元数据
}
```

**Finding 的线程安全方法：**

```go
// 添加单个数据条目
func (f *Finding) AddDataEntry(key string, data interface{})

// 批量添加数据条目
func (f *Finding) AddDataEntries(dataBatch map[string]interface{})

// 获取数据的安全副本
func (f *Finding) GetData() map[string]interface{}
```

### 3.6 protocol.Event 结构

```go
// Event 是引擎可以处理的通用事件
type Event struct {
    Headers EventHeaders
    Payload interface{}  // 通常是 trace.Event
}

type EventHeaders struct {
    Selector Selector          // 用于过滤的选择器
    custom   map[string]string // 自定义头部
}

type Selector struct {
    Name   string  // 事件名称
    Origin string  // 来源（host/container）
    Source string  // 生产者（tracee）
}
```

---

## 4. 签名类型对比：Go 签名 vs Rego 签名

### 4.1 Go 签名

**优点：**
- 完整的 Go 语言能力（复杂逻辑、状态管理、并发）
- 高性能，无解释开销
- 可以使用任何 Go 库
- 调试方便

**缺点：**
- 需要编译
- 需要 Go 开发经验
- 动态加载需要 plugin 机制

**适用场景：**
- 复杂的多事件关联检测
- 需要维护状态的检测
- 性能敏感的检测

### 4.2 Rego 签名（OPA）

**优点：**
- 声明式策略语言
- 无需编译，动态加载
- 易于安全审计
- 与 OPA 生态兼容

**缺点：**
- 学习曲线
- 功能受限
- 性能相对较低

**适用场景：**
- 简单的模式匹配
- 策略驱动的检测
- 需要动态更新规则

### 4.3 对比表

| 特性 | Go 签名 | Rego 签名 |
|------|---------|-----------|
| 性能 | 高 | 中 |
| 开发难度 | 中 | 低-中 |
| 状态管理 | 原生支持 | 有限 |
| 动态加载 | 需要 plugin | 原生支持 |
| 调试 | 方便 | 一般 |
| 生态 | Go 生态 | OPA 生态 |

---

## 5. SignaturesEngine 实现详解

### 5.1 Engine 结构体

```go
// pkg/signatures/engine/engine.go

type Engine struct {
    signatures       map[detect.Signature]struct{}           // 所有加载的签名
    signaturesIndex  map[detect.SignatureEventSelector][]detect.Signature // 事件到签名的索引
    signaturesMutex  sync.RWMutex                            // 并发保护
    inputs           EventSources                             // 输入事件源
    output           chan *detect.Finding                     // 输出通道
    config           Config                                   // 配置
    stats            metrics.Stats                            // 统计信息
    dataSources      map[string]map[string]detect.DataSource // 数据源
    dataSourcesMutex sync.RWMutex
    ctx              context.Context
}
```

### 5.2 Engine 配置

```go
type Config struct {
    Mode                Mode               // 运行模式
    NoSignatures        bool               // 跳过签名处理
    AvailableSignatures []detect.Signature // 所有可用签名
    SelectedSignatures  []detect.Signature // 选中加载的签名
    DataSources         []detect.DataSource
}

type Mode uint8

const (
    ModeRules        Mode = iota  // 管道模式
    ModeAnalyze                    // 分析模式
    ModeSingleBinary               // 单二进制模式
)
```

### 5.3 事件处理核心逻辑

```go
func (engine *Engine) processEvent(event protocol.Event) {
    engine.signaturesMutex.RLock()
    defer engine.signaturesMutex.RUnlock()

    _ = engine.stats.Events.Increment()

    // 预计算所有选择器模式
    sourceSelector := event.Headers.Selector.Source
    nameSelector := event.Headers.Selector.Name
    originSelector := event.Headers.Selector.Origin

    // 构建 4 种匹配模式
    selectors := [4]detect.SignatureEventSelector{
        // 完全匹配
        {Source: sourceSelector, Name: nameSelector, Origin: originSelector},
        // 部分匹配，选择所有来源
        {Source: sourceSelector, Name: nameSelector, Origin: ALL_EVENT_ORIGINS},
        // 部分匹配，选择所有事件名
        {Source: sourceSelector, Name: ALL_EVENT_TYPES, Origin: originSelector},
        // 部分匹配，选择所有来源和事件名
        {Source: sourceSelector, Name: ALL_EVENT_TYPES, Origin: ALL_EVENT_ORIGINS},
    }

    // 遍历所有选择器模式查找匹配的签名
    for i := range selectors {
        for _, s := range engine.signaturesIndex[selectors[i]] {
            engine.dispatchEvent(s, event)
        }
    }
}
```

### 5.4 签名加载流程

```go
func (engine *Engine) loadSignature(signature detect.Signature) (string, error) {
    // 1. 获取签名元数据
    metadata, err := signature.GetMetadata()
    if err != nil {
        return "", fmt.Errorf("error getting metadata: %w", err)
    }

    // 2. 获取订阅的事件
    selectedEvents, err := signature.GetSelectedEvents()
    if err != nil {
        return "", fmt.Errorf("error getting selected events: %w", err)
    }

    // 3. 检查重复
    engine.signaturesMutex.RLock()
    for existingSig := range engine.signatures {
        existingMetadata, _ := existingSig.GetMetadata()
        if existingMetadata.ID == metadata.ID {
            engine.signaturesMutex.RUnlock()
            return "", fmt.Errorf("signature \"%s\" already loaded", metadata.Name)
        }
    }
    engine.signaturesMutex.RUnlock()

    // 4. 创建签名上下文
    signatureCtx := detect.SignatureContext{
        Callback: engine.matchHandler,
        Logger:   logger.Current(),
        GetDataSource: func(namespace, id string) (detect.DataSource, bool) {
            return engine.GetDataSource(namespace, id)
        },
    }

    // 5. 初始化签名
    if err := signature.Init(signatureCtx); err != nil {
        return "", fmt.Errorf("error initializing signature: %w", err)
    }

    // 6. 添加到签名集合
    engine.signaturesMutex.Lock()
    engine.signatures[signature] = struct{}{}
    engine.signaturesMutex.Unlock()

    // 7. 建立事件索引
    for _, selectedEvent := range selectedEvents {
        if selectedEvent.Name == "" {
            selectedEvent.Name = ALL_EVENT_TYPES
        }
        if selectedEvent.Origin == "" {
            selectedEvent.Origin = ALL_EVENT_ORIGINS
        }
        engine.signaturesMutex.Lock()
        engine.signaturesIndex[selectedEvent] = append(
            engine.signaturesIndex[selectedEvent], signature)
        engine.signaturesMutex.Unlock()
    }

    _ = engine.stats.Signatures.Increment()
    return metadata.ID, nil
}
```

### 5.5 匹配处理器

```go
func (engine *Engine) matchHandler(res *detect.Finding) {
    _ = engine.stats.Detections.Increment()

    select {
    case engine.output <- res:  // 发送到输出通道
    case <-engine.ctx.Done():
        return
    }

    // 分析模式下的反馈机制
    if engine.config.Mode == ModeAnalyze {
        e, err := findings.FindingToEvent(res)
        if err != nil {
            logger.Errorw("Failed to convert finding to event", "err", err)
            return
        }
        prot := e.ToProtocol()
        select {
        case engine.inputs.Tracee <- prot:
        case <-engine.ctx.Done():
            return
        }
    }
}
```

---

## 6. 签名生命周期

### 6.1 完整生命周期图

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        Signature Lifecycle                              │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│   ┌──────────┐      ┌──────────┐      ┌──────────┐      ┌──────────┐  │
│   │ Discovery│─────►│  Loading │─────►│   Init   │─────►│  Active  │  │
│   │          │      │          │      │          │      │          │  │
│   └──────────┘      └──────────┘      └──────────┘      └──────────┘  │
│        │                 │                  │                 │        │
│        ▼                 ▼                  ▼                 ▼        │
│   Find .so files   GetMetadata()      Init(ctx)         OnEvent()     │
│   Load plugin      GetSelectedEvents  Save callback      Process      │
│   Lookup Export    Build index        Init state         Match        │
│                                                          Report       │
│                                                                         │
│                                                          ┌──────────┐  │
│                                        OnSignal()───────►│ Cleanup  │  │
│                                                          │          │  │
│                                                          └──────────┘  │
│                                                               │        │
│                                                               ▼        │
│                                                          Close()       │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### 6.2 阶段详解

#### 阶段 1：Discovery（发现）

```go
// pkg/signatures/signature/signature.go

func Find(signaturesDir []string, signatures []string) ([]detect.Signature, []detect.DataSource, error) {
    // 1. 确定签名目录
    if len(signaturesDir) == 0 {
        exePath, _ := os.Executable()
        signaturesDir = []string{filepath.Join(filepath.Dir(exePath), "signatures")}
    }

    var sigs []detect.Signature
    var datasources []detect.DataSource

    // 2. 遍历目录查找签名
    for _, dir := range signaturesDir {
        gosigs, ds, err := findGoSigs(dir)
        sigs = append(sigs, gosigs...)
        datasources = append(datasources, ds...)
    }

    return sigs, datasources, nil
}

func findGoSigs(dir string) ([]detect.Signature, []detect.DataSource, error) {
    // 遍历目录查找 .so 文件
    filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
        if d.IsDir() || filepath.Ext(d.Name()) != ".so" {
            return nil
        }

        // 加载插件
        p, err := plugin.Open(path)

        // 查找导出符号
        exportSigs, err := p.Lookup("ExportedSignatures")
        sigs := *exportSigs.(*[]detect.Signature)

        return nil
    })
}
```

#### 阶段 2：Loading（加载）

```go
// Engine.Init() 调用
for _, sig := range engine.config.SelectedSignatures {
    _, err := engine.loadSignature(sig)
    if err != nil {
        logger.Errorw("Loading signature: " + err.Error())
    }
}
```

#### 阶段 3：Init（初始化）

```go
// 签名的 Init 方法
func (sig *MySignature) Init(ctx detect.SignatureContext) error {
    // 1. 保存回调函数
    sig.cb = ctx.Callback

    // 2. 初始化内部状态
    sig.count = 0
    sig.pattern = regexp.MustCompile(`...`)

    // 3. 可选：访问数据源
    ds, ok := ctx.GetDataSource("namespace", "id")

    return nil
}
```

#### 阶段 4：Active（活跃运行）

```go
// 引擎分发事件到签名
func (engine *Engine) dispatchEvent(s detect.Signature, event protocol.Event) {
    if err := s.OnEvent(event); err != nil {
        meta, _ := s.GetMetadata()
        logger.Errorw("Processing event", "signature", meta.Name, "error", err)
    }
}

// 签名处理事件
func (sig *MySignature) OnEvent(event protocol.Event) error {
    eventObj, ok := event.Payload.(trace.Event)
    if !ok {
        return errors.New("invalid event")
    }

    // 检测逻辑...

    if detected {
        sig.cb(&detect.Finding{
            SigMetadata: metadata,
            Event:       event,
            Data:        additionalData,
        })
    }

    return nil
}
```

#### 阶段 5：Signal（信号处理）

```go
// 处理生命周期信号
func (sig *MySignature) OnSignal(signal detect.Signal) error {
    source, sigcomplete := signal.(detect.SignalSourceComplete)
    if sigcomplete && source == "tracee" {
        // 数据源已结束，可以进行最终处理
        sig.finalReport()
    }
    return nil
}
```

#### 阶段 6：Cleanup（清理）

```go
// 清理资源
func (sig *MySignature) Close() {
    // 关闭文件句柄
    // 释放资源
    // 清理状态
}
```

---

## 7. 内置签名分析

### 7.1 AntiDebuggingPtraceme - 反调试检测

**文件位置：** `signatures/golang/anti_debugging_ptraceme.go`

**检测目标：** 检测进程使用 `ptrace(PTRACE_TRACEME)` 进行反调试

```go
type AntiDebuggingPtraceme struct {
    cb            detect.SignatureHandler
    ptraceTraceMe int  // PTRACE_TRACEME 的值
}

func (sig *AntiDebuggingPtraceme) Init(ctx detect.SignatureContext) error {
    sig.cb = ctx.Callback
    sig.ptraceTraceMe = int(parsers.PTRACE_TRACEME.Value())
    return nil
}

func (sig *AntiDebuggingPtraceme) GetMetadata() (detect.SignatureMetadata, error) {
    return detect.SignatureMetadata{
        ID:          "TRC-102",
        Version:     "1",
        Name:        "Anti-Debugging detected",
        EventName:   "anti_debugging",
        Description: "A process used anti-debugging techniques to block a debugger...",
        Properties: map[string]interface{}{
            "Severity":    1,
            "Category":    "defense-evasion",
            "Technique":   "Debugger Evasion",
            "external_id": "T1622",
        },
    }, nil
}

func (sig *AntiDebuggingPtraceme) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
    return []detect.SignatureEventSelector{
        {Source: "tracee", Name: "ptrace", Origin: "*"},
    }, nil
}

func (sig *AntiDebuggingPtraceme) OnEvent(event protocol.Event) error {
    eventObj, ok := event.Payload.(trace.Event)
    if !ok {
        return errors.New("invalid event")
    }

    switch eventObj.EventName {
    case "ptrace":
        // 获取 ptrace 的 request 参数
        requestArg, err := eventObj.GetIntArgumentByName("request")
        if err != nil {
            return err
        }

        // 检查是否是 PTRACE_TRACEME
        if requestArg == sig.ptraceTraceMe {
            metadata, _ := sig.GetMetadata()
            sig.cb(&detect.Finding{
                SigMetadata: metadata,
                Event:       event,
                Data:        nil,
            })
        }
    }
    return nil
}
```

**技术要点：**
- 简单的单事件匹配
- 使用 `parsers` 包获取系统常量
- 通过参数名获取事件参数

### 7.2 StdioOverSocket - 反弹 Shell 检测

**文件位置：** `signatures/golang/stdio_over_socket.go`

**检测目标：** 检测标准输入/输出被重定向到 socket（反弹 Shell 的基础）

```go
type StdioOverSocket struct {
    cb         detect.SignatureHandler
    legitPorts []string  // 合法端口白名单
}

func (sig *StdioOverSocket) Init(ctx detect.SignatureContext) error {
    sig.cb = ctx.Callback
    sig.legitPorts = []string{"", "0"}
    return nil
}

func (sig *StdioOverSocket) GetMetadata() (detect.SignatureMetadata, error) {
    return detect.SignatureMetadata{
        ID:          "TRC-101",
        Version:     "2",
        Name:        "Process standard input/output over socket detected",
        EventName:   "stdio_over_socket",
        Description: "A process has its standard input/output redirected to a socket...",
        Properties: map[string]interface{}{
            "Severity":    3,
            "Category":    "execution",
            "Technique":   "Unix Shell",
            "external_id": "T1059.004",
        },
    }, nil
}

func (sig *StdioOverSocket) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
    return []detect.SignatureEventSelector{
        {Source: "tracee", Name: "security_socket_connect", Origin: "*"},
        {Source: "tracee", Name: "socket_dup", Origin: "*"},
    }, nil
}

func (sig *StdioOverSocket) OnEvent(event protocol.Event) error {
    eventObj, ok := event.Payload.(trace.Event)
    if !ok {
        return errors.New("invalid event")
    }

    var sockfd int
    var err error

    // 根据事件类型获取 socket fd
    switch eventObj.EventName {
    case "security_socket_connect":
        sockfd, err = eventObj.GetIntArgumentByName("sockfd")
    case "socket_dup":
        sockfd, err = eventObj.GetIntArgumentByName("newfd")
    }
    if err != nil {
        return err
    }

    // 检查是否是标准输入/输出/错误
    if sockfd != 0 && sockfd != 1 && sockfd != 2 {
        return nil
    }

    // 获取远程地址
    remoteAddr, err := eventObj.GetRawAddrArgumentByName("remote_addr")
    if err != nil {
        return err
    }

    // 验证是网络地址族
    supportedFamily, _ := parsers.IsInternetFamily(remoteAddr)
    if !supportedFamily {
        return nil
    }

    // 检查端口
    port, _ := parsers.GetPortFromRawAddr(remoteAddr)
    for _, legitPort := range sig.legitPorts {
        if port == legitPort {
            return nil
        }
    }

    // 获取 IP 地址
    ip, _ := parsers.GetIPFromRawAddr(remoteAddr)

    metadata, _ := sig.GetMetadata()
    sig.cb(&detect.Finding{
        SigMetadata: metadata,
        Event:       event,
        Data: map[string]interface{}{
            "IP address":      ip,
            "Port":            port,
            "File descriptor": sockfd,
        },
    })

    return nil
}
```

**技术要点：**
- 多事件订阅
- 使用白名单过滤
- 在 Finding 中添加额外数据
- 使用 parsers 包解析网络地址

### 7.3 LdPreload - LD_PRELOAD 注入检测

**文件位置：** `signatures/golang/ld_preload.go`

**检测目标：** 检测 LD_PRELOAD 的使用（代码注入技术）

```go
type LdPreload struct {
    cb          detect.SignatureHandler
    preloadEnvs []string
    preloadPath string
}

func (sig *LdPreload) Init(ctx detect.SignatureContext) error {
    sig.cb = ctx.Callback
    sig.preloadEnvs = []string{"LD_PRELOAD", "LD_LIBRARY_PATH"}
    sig.preloadPath = "/etc/ld.so.preload"
    return nil
}

func (sig *LdPreload) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
    return []detect.SignatureEventSelector{
        {Source: "tracee", Name: "sched_process_exec", Origin: "*"},
        {Source: "tracee", Name: "security_file_open", Origin: "*"},
        {Source: "tracee", Name: "security_inode_rename", Origin: "*"},
    }, nil
}

func (sig *LdPreload) OnEvent(event protocol.Event) error {
    eventObj, ok := event.Payload.(trace.Event)
    if !ok {
        return errors.New("invalid event")
    }

    switch eventObj.EventName {
    case "sched_process_exec":
        // 检查环境变量中是否有 LD_PRELOAD
        envVars, err := eventObj.GetSliceStringArgumentByName("env")
        if err != nil {
            return nil
        }

        for _, envVar := range envVars {
            for _, preloadEnv := range sig.preloadEnvs {
                if strings.HasPrefix(envVar, preloadEnv+"=") {
                    metadata, _ := sig.GetMetadata()
                    sig.cb(&detect.Finding{
                        SigMetadata: metadata,
                        Event:       event,
                        Data:        map[string]interface{}{preloadEnv: envVar},
                    })
                    return nil
                }
            }
        }

    case "security_file_open":
        // 检查是否写入 /etc/ld.so.preload
        pathname, _ := eventObj.GetStringArgumentByName("pathname")
        flags, _ := eventObj.GetIntArgumentByName("flags")

        if strings.HasSuffix(pathname, sig.preloadPath) && parsers.IsFileWrite(flags) {
            metadata, _ := sig.GetMetadata()
            sig.cb(&detect.Finding{
                SigMetadata: metadata,
                Event:       event,
            })
        }

    case "security_inode_rename":
        // 检查是否重命名文件到 /etc/ld.so.preload
        newPath, _ := eventObj.GetStringArgumentByName("new_path")

        if strings.HasSuffix(newPath, sig.preloadPath) {
            metadata, _ := sig.GetMetadata()
            sig.cb(&detect.Finding{
                SigMetadata: metadata,
                Event:       event,
            })
        }
    }

    return nil
}
```

**技术要点：**
- 多种检测模式（环境变量、文件写入、文件重命名）
- 字符串匹配和前缀检查
- 文件操作标志解析

### 7.4 ProcMemCodeInjection - 进程内存注入检测

**文件位置：** `signatures/golang/proc_mem_code_injection.go`

**检测目标：** 检测通过 `/proc/<pid>/mem` 进行的代码注入

```go
type ProcMemCodeInjection struct {
    cb                 detect.SignatureHandler
    procMemPathPattern string
    compiledRegex      *regexp.Regexp
}

func (sig *ProcMemCodeInjection) Init(ctx detect.SignatureContext) error {
    var err error
    sig.cb = ctx.Callback
    sig.procMemPathPattern = `/proc/(?:\d.+)/mem$`
    sig.compiledRegex, err = regexp.Compile(sig.procMemPathPattern)
    return err
}

func (sig *ProcMemCodeInjection) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
    return []detect.SignatureEventSelector{
        {Source: "tracee", Name: "security_file_open", Origin: "*"},
    }, nil
}

func (sig *ProcMemCodeInjection) OnEvent(event protocol.Event) error {
    eventObj, ok := event.Payload.(trace.Event)
    if !ok {
        return errors.New("invalid event")
    }

    switch eventObj.EventName {
    case "security_file_open":
        pathname, _ := eventObj.GetStringArgumentByName("pathname")
        flags, _ := eventObj.GetIntArgumentByName("flags")

        // 使用正则匹配路径，并检查是否是写入操作
        if parsers.IsFileWrite(flags) && sig.compiledRegex.MatchString(pathname) {
            metadata, _ := sig.GetMetadata()
            sig.cb(&detect.Finding{
                SigMetadata: metadata,
                Event:       event,
            })
        }
    }

    return nil
}
```

**技术要点：**
- 在 Init 中预编译正则表达式
- 正则表达式模式匹配

### 7.5 SyscallTableHooking - 系统调用表 Hook 检测

**文件位置：** `signatures/golang/syscall_table_hooking.go`

**检测目标：** 检测内核系统调用表被 hook（Rootkit 常用技术）

```go
type SyscallTableHooking struct {
    cb detect.SignatureHandler
}

func (sig *SyscallTableHooking) Init(ctx detect.SignatureContext) error {
    sig.cb = ctx.Callback
    return nil
}

func (sig *SyscallTableHooking) GetMetadata() (detect.SignatureMetadata, error) {
    return detect.SignatureMetadata{
        ID:          "TRC-1030",
        Version:     "1",
        Name:        "Syscall table hooking detected",
        EventName:   "syscall_hooking",
        Description: "Syscall table hooking detected. Syscalls are the interface between user applications and the kernel...",
        Properties: map[string]interface{}{
            "Severity":    3,
            "Category":    "defense-evasion",
            "Technique":   "Rootkit",
            "external_id": "T1014",
        },
    }, nil
}

func (sig *SyscallTableHooking) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
    return []detect.SignatureEventSelector{
        {Source: "tracee", Name: "hooked_syscall", Origin: "*"},
    }, nil
}

func (sig *SyscallTableHooking) OnEvent(event protocol.Event) error {
    eventObj, ok := event.Payload.(trace.Event)
    if !ok {
        return errors.New("invalid event")
    }

    switch eventObj.EventName {
    case "hooked_syscall":
        // hooked_syscall 事件本身就表示检测到了 hook
        metadata, _ := sig.GetMetadata()
        sig.cb(&detect.Finding{
            SigMetadata: metadata,
            Event:       event,
        })
    }

    return nil
}
```

**技术要点：**
- 最简单的签名模式 - 事件存在即报警
- 依赖 Tracee 内核检测能力

---

## 8. 自定义签名开发完整指南

### 8.1 开发流程

```
1. 需求分析 → 2. 事件选择 → 3. 签名实现 → 4. 单元测试 → 5. 编译部署
```

### 8.2 签名模板

```go
package main

import (
    "errors"

    "github.com/aquasecurity/tracee/types/detect"
    "github.com/aquasecurity/tracee/types/protocol"
    "github.com/aquasecurity/tracee/types/trace"
)

// MyCustomSignature 自定义签名结构体
type MyCustomSignature struct {
    cb detect.SignatureHandler
    // 添加你需要的状态字段
}

// Init 初始化签名
func (sig *MyCustomSignature) Init(ctx detect.SignatureContext) error {
    sig.cb = ctx.Callback
    // 初始化你的状态
    return nil
}

// GetMetadata 返回签名元信息
func (sig *MyCustomSignature) GetMetadata() (detect.SignatureMetadata, error) {
    return detect.SignatureMetadata{
        ID:          "TRC-CUSTOM-001",
        Version:     "1",
        Name:        "My Custom Detection",
        EventName:   "my_custom_event",
        Description: "Detects something important",
        Properties: map[string]interface{}{
            "Severity":    2,
            "Category":    "detection",
            "Technique":   "Custom Technique",
            "external_id": "T0000",
        },
    }, nil
}

// GetSelectedEvents 声明订阅的事件
func (sig *MyCustomSignature) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
    return []detect.SignatureEventSelector{
        {Source: "tracee", Name: "your_event_name", Origin: "*"},
    }, nil
}

// OnEvent 处理事件的核心逻辑
func (sig *MyCustomSignature) OnEvent(event protocol.Event) error {
    eventObj, ok := event.Payload.(trace.Event)
    if !ok {
        return errors.New("invalid event")
    }

    switch eventObj.EventName {
    case "your_event_name":
        // 你的检测逻辑
        if /* 检测条件 */ true {
            metadata, err := sig.GetMetadata()
            if err != nil {
                return err
            }
            sig.cb(&detect.Finding{
                SigMetadata: metadata,
                Event:       event,
                Data: map[string]interface{}{
                    "key": "value",
                },
            })
        }
    }

    return nil
}

// OnSignal 处理生命周期信号
func (sig *MyCustomSignature) OnSignal(s detect.Signal) error {
    return nil
}

// Close 清理资源
func (sig *MyCustomSignature) Close() {}
```

### 8.3 导出签名

创建 `export.go` 文件：

```go
package main

import "github.com/aquasecurity/tracee/types/detect"

// ExportedSignatures 导出签名列表
var ExportedSignatures = []detect.Signature{
    &MyCustomSignature{},
    // 添加更多签名...
}

// ExportedDataSources 导出数据源列表
var ExportedDataSources = []detect.DataSource{
    // 如果有数据源...
}
```

### 8.4 编译签名插件

```bash
# 编译为共享库
go build -buildmode=plugin -o signatures/my_signatures.so ./path/to/signatures/

# 或使用 Makefile
make signatures
```

### 8.5 常用事件参数获取方法

```go
// 获取字符串参数
pathname, err := eventObj.GetStringArgumentByName("pathname")

// 获取整数参数
flags, err := eventObj.GetIntArgumentByName("flags")

// 获取字符串切片参数
envVars, err := eventObj.GetSliceStringArgumentByName("env")

// 获取原始地址参数
remoteAddr, err := eventObj.GetRawAddrArgumentByName("remote_addr")
```

### 8.6 测试签名

创建测试文件 `my_signature_test.go`：

```go
package main

import (
    "testing"

    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"

    "github.com/aquasecurity/tracee/types/detect"
    "github.com/aquasecurity/tracee/types/trace"
)

func TestMyCustomSignature(t *testing.T) {
    testCases := []struct {
        name           string
        event          trace.Event
        expectFinding  bool
    }{
        {
            name: "should detect malicious pattern",
            event: trace.Event{
                EventName: "your_event_name",
                Args: []trace.Argument{
                    {ArgMeta: trace.ArgMeta{Name: "pathname"}, Value: "/malicious/path"},
                },
            },
            expectFinding: true,
        },
        {
            name: "should not detect benign pattern",
            event: trace.Event{
                EventName: "your_event_name",
                Args: []trace.Argument{
                    {ArgMeta: trace.ArgMeta{Name: "pathname"}, Value: "/normal/path"},
                },
            },
            expectFinding: false,
        },
    }

    for _, tc := range testCases {
        t.Run(tc.name, func(t *testing.T) {
            sig := MyCustomSignature{}

            var gotFinding *detect.Finding

            err := sig.Init(detect.SignatureContext{
                Callback: func(f *detect.Finding) {
                    gotFinding = f
                },
            })
            require.NoError(t, err)

            err = sig.OnEvent(tc.event.ToProtocol())
            require.NoError(t, err)

            if tc.expectFinding {
                assert.NotNil(t, gotFinding)
            } else {
                assert.Nil(t, gotFinding)
            }
        })
    }
}
```

---

## 9. 动手练习

### 练习 1：简单签名 - 敏感文件访问检测（难度：初级）

**目标：** 检测对 `/etc/shadow` 文件的访问

**提示：**
- 订阅 `security_file_open` 事件
- 检查 `pathname` 参数

**参考框架：**

```go
type ShadowFileAccess struct {
    cb detect.SignatureHandler
}

func (sig *ShadowFileAccess) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
    return []detect.SignatureEventSelector{
        {Source: "tracee", Name: "security_file_open", Origin: "*"},
    }, nil
}

func (sig *ShadowFileAccess) OnEvent(event protocol.Event) error {
    // 实现你的检测逻辑
    // 1. 转换事件
    // 2. 获取 pathname 参数
    // 3. 检查是否是 /etc/shadow
    // 4. 如果匹配，调用回调
    return nil
}
```

### 练习 2：多事件关联 - 可疑进程行为检测（难度：中级）

**目标：** 检测进程先执行 `wget` 或 `curl` 下载，然后执行下载的文件

**提示：**
- 需要维护状态跟踪下载行为
- 订阅 `sched_process_exec` 事件
- 关联同一进程的多个事件

### 练习 3：状态机签名 - 暴力破解检测（难度：高级）

**目标：** 检测 SSH 暴力破解攻击（短时间内多次失败登录）

**提示：**
- 维护登录失败计数器
- 使用时间窗口
- 考虑并发安全

### 练习 4：使用数据源 - 容器感知检测（难度：高级）

**目标：** 创建一个使用容器数据源的签名，检测特权容器中的可疑行为

**提示：**
- 使用 `ctx.GetDataSource()` 访问数据源
- 结合容器信息进行检测

---

## 10. 核心代码走读

### 10.1 Engine 初始化流程

```go
// 文件: pkg/signatures/engine/engine.go

// 1. 创建引擎
func NewEngine(config Config, sources EventSources, output chan *detect.Finding) (*Engine, error) {
    if sources.Tracee == nil || output == nil {
        return nil, errors.New("nil input received")
    }

    engine := Engine{
        inputs:  sources,
        output:  output,
        config:  config,
    }

    // 初始化签名存储
    engine.signatures = make(map[detect.Signature]struct{})
    engine.signaturesIndex = make(map[detect.SignatureEventSelector][]detect.Signature)
    engine.dataSources = map[string]map[string]detect.DataSource{}

    return &engine, nil
}

// 2. 初始化（加载签名和数据源）
func (engine *Engine) Init() error {
    // 加载数据源
    for _, dataSource := range engine.config.DataSources {
        engine.RegisterDataSource(dataSource)
    }

    // 加载签名
    for _, sig := range engine.config.SelectedSignatures {
        engine.loadSignature(sig)
    }

    return nil
}

// 3. 启动引擎
func (engine *Engine) Start(ctx context.Context) {
    defer engine.unloadAllSignatures()
    engine.ctx = ctx
    engine.consumeSources()
}
```

### 10.2 事件消费循环

```go
// 文件: pkg/signatures/engine/engine.go

func (engine *Engine) consumeSources() {
    for {
        select {
        case event, ok := <-engine.inputs.Tracee:
            if !ok {
                // 通道关闭，通知签名
                for sig := range engine.signatures {
                    se, _ := sig.GetSelectedEvents()
                    for _, sel := range se {
                        if sel.Source == "tracee" {
                            sig.OnSignal(detect.SignalSourceComplete("tracee"))
                            break
                        }
                    }
                }
                engine.inputs.Tracee = nil
                if engine.checkCompletion() {
                    return
                }
                continue
            }
            // 处理事件
            engine.processEvent(event)

        case <-engine.ctx.Done():
            goto drain
        }
    }

drain:
    // 排空剩余事件
    for {
        select {
        case event := <-engine.inputs.Tracee:
            engine.processEvent(event)
        default:
            return
        }
    }
}
```

### 10.3 签名查找与插件加载

```go
// 文件: pkg/signatures/signature/signature.go

func findGoSigs(dir string) ([]detect.Signature, []detect.DataSource, error) {
    var signatures []detect.Signature
    var datasources []detect.DataSource

    // 检查是否是静态二进制
    if isBinaryStatic() {
        logger.Warnw("The tracee static can't load golang signatures")
        return signatures, datasources, nil
    }

    // 遍历目录
    filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
        // 跳过目录和非 .so 文件
        if d.IsDir() || filepath.Ext(d.Name()) != ".so" {
            return nil
        }

        // 加载插件
        p, err := plugin.Open(path)
        if err != nil {
            return err
        }

        // 查找导出的签名
        exportSigs, err := p.Lookup("ExportedSignatures")
        sigs := *exportSigs.(*[]detect.Signature)

        // 查找导出的数据源
        exportDS, _ := p.Lookup("ExportedDataSources")
        if exportDS != nil {
            ds := *exportDS.(*[]detect.DataSource)
            datasources = append(datasources, ds...)
        }

        signatures = append(signatures, sigs...)
        return nil
    })

    return signatures, datasources, nil
}
```

### 10.4 统计指标

```go
// 文件: pkg/signatures/metrics/stats.go

type Stats struct {
    Events     counter.Counter  // 处理的事件数
    Signatures counter.Counter  // 加载的签名数
    Detections counter.Counter  // 检测到的威胁数
}

// Prometheus 指标注册
func (stats *Stats) RegisterPrometheus() error {
    prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
        Namespace: "tracee_rules",
        Name:      "events_total",
        Help:      "events ingested by tracee-rules",
    }, func() float64 { return float64(stats.Events.Get()) }))

    prometheus.Register(prometheus.NewCounterFunc(prometheus.CounterOpts{
        Namespace: "tracee_rules",
        Name:      "detections_total",
        Help:      "detections made by tracee-rules",
    }, func() float64 { return float64(stats.Detections.Get()) }))

    prometheus.Register(prometheus.NewGaugeFunc(prometheus.GaugeOpts{
        Namespace: "tracee_rules",
        Name:      "signatures_total",
        Help:      "signatures loaded",
    }, func() float64 { return float64(stats.Signatures.Get()) }))

    return nil
}
```

---

## 附录

### A. 常用事件列表

| 事件名 | 描述 | 常用参数 |
|--------|------|----------|
| `sched_process_exec` | 进程执行 | pathname, argv, env |
| `security_file_open` | 文件打开 | pathname, flags |
| `ptrace` | ptrace 调用 | request, pid |
| `security_socket_connect` | Socket 连接 | sockfd, remote_addr |
| `module_load` | 内核模块加载 | name |
| `hooked_syscall` | 检测到 Syscall Hook | syscall |
| `security_inode_rename` | 文件重命名 | old_path, new_path |

### B. MITRE ATT&CK 映射

| 签名 ID | 技术 | ATT&CK ID |
|---------|------|-----------|
| TRC-101 | Reverse Shell | T1059.004 |
| TRC-102 | Anti-Debugging | T1622 |
| TRC-105 | Fileless Execution | T1620 |
| TRC-107 | LD_PRELOAD Injection | T1574 |
| TRC-1017 | Kernel Module Loading | T1547.006 |
| TRC-1030 | Syscall Hooking | T1014 |

### C. 调试技巧

```bash
# 1. 启用详细日志
tracee --log level=debug

# 2. 只运行特定签名
tracee --signatures TRC-102

# 3. 输出 JSON 格式便于分析
tracee --output json

# 4. 使用 analyze 模式测试签名
tracee analyze --signatures ./my_signature.so events.json
```

### D. 参考资源

- [Tracee 官方文档](https://aquasecurity.github.io/tracee/)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Go Plugin 文档](https://pkg.go.dev/plugin)
- [Tracee GitHub 仓库](https://github.com/aquasecurity/tracee)

---

## 总结

通过本教程，你学习了：

1. **签名引擎架构**：理解了事件流、签名索引、匹配分发的工作机制
2. **核心接口**：掌握了 Signature、Finding、SignatureEventSelector 等核心类型
3. **签名生命周期**：从发现到加载、初始化、运行、清理的完整流程
4. **内置签名分析**：深入分析了多个实际签名的实现
5. **自定义开发**：学会了开发、测试、部署自定义签名

下一步，尝试完成动手练习，并在实际环境中测试你的签名！
