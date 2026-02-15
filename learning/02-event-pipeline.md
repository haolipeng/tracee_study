# Tracee 源代码学习指南 - 第二阶段：事件处理流水线

> **学习目标**：深入理解事件从内核到用户空间的完整数据流和处理逻辑
> **预计时间**：3-5 天
> **前置知识**：完成第一阶段学习，理解 Go channel 和 goroutine

---

## 📋 目录

1. [流水线架构概述](#1-流水线架构概述)
2. [事件定义系统](#2-事件定义系统)
3. [流水线各阶段详解](#3-流水线各阶段详解)
4. [事件解码机制](#4-事件解码机制)
5. [事件派生系统](#5-事件派生系统)
6. [实践练习](#6-实践练习)

---

## 1. 流水线架构概述

### 1.1 完整流水线图

```
┌─────────────────────────────────────────────────────────────────┐
│                      事件处理流水线 Pipeline                       │
└─────────────────────────────────────────────────────────────────┘

  内核空间                           用户空间
     │                                  │
     ▼                                  ▼
┌──────────┐                    ┌──────────────┐
│ eBPF 程序 │ ─── Perf ────────▶│ eventsChannel│
│ (内核态)  │    Buffer          │  (原始字节)   │
└──────────┘                    └──────┬───────┘
                                       │
                     ┌─────────────────┴─────────────────┐
                     │   handleEvents() 主流水线          │
                     └─────────────────┬─────────────────┘
                                       │
        ┌──────────────────────────────┼──────────────────────────────┐
        │                              │                              │
        ▼                              ▼                              ▼
┌───────────────┐            ┌───────────────┐            ┌──────────────┐
│  阶段1: 解码   │            │  阶段2: 排序   │            │  阶段3: 处理  │
│   Decode      │            │   Sort        │            │   Process    │
│               │            │  (可选)        │            │              │
│ 原始字节      │            │ 时序调整       │            │ 参数提取     │
│   ↓           │            │               │            │ 类型转换     │
│ trace.Event   │            │ 确保顺序      │            │ 处理器执行   │
└───────┬───────┘            └───────┬───────┘            └──────┬───────┘
        │                            │                            │
        │        chan *trace.Event   │      chan *trace.Event     │
        └────────────────────────────┴────────────────────────────┘
                                     │
        ┌────────────────────────────┼────────────────────────────┐
        │                            │                            │
        ▼                            ▼                            ▼
┌───────────────┐            ┌──────────────┐           ┌──────────────┐
│  阶段4: 丰富   │            │  阶段5: 派生  │           │  阶段6: 引擎  │
│   Enrich      │            │   Derive     │           │   Engine     │
│               │            │              │           │              │
│ 添加容器信息   │            │ 生成派生事件  │           │ 规则匹配     │
│ K8s 元数据    │            │ (如DNS响应)   │           │ 安全检测     │
│ 镜像信息      │            │              │           │ 生成Finding  │
└───────┬───────┘            └──────┬───────┘           └──────┬───────┘
        │                           │                          │
        │        chan *trace.Event  │     chan *trace.Event    │
        └───────────────────────────┴──────────────────────────┘
                                    │
                                    ▼
                          ┌──────────────────┐
                          │   阶段7: 输出     │
                          │    Sink          │
                          │                  │
                          │ • JSON 输出      │
                          │ • Table 输出     │
                          │ • Webhook        │
                          │ • gRPC Stream    │
                          └──────────────────┘
```

### 1.2 核心实现 - [pkg/ebpf/events_pipeline.go:33](pkg/ebpf/events_pipeline.go#L33)

```go
func (t *Tracee) handleEvents(ctx context.Context, initialized chan<- struct{}) {
    logger.Debugw("Starting handleEvents goroutine")
    defer logger.Debugw("Stopped handleEvents goroutine")

    var errcList []<-chan error

    // ========== 阶段1: 解码 (Decode) ==========
    // 从 perf buffer 读取原始字节，解码为 trace.Event
    eventsChan, errc := t.decodeEvents(ctx, t.eventsChannel)
    t.stats.Channels["decode"] = eventsChan
    errcList = append(errcList, errc)

    // ========== 阶段2: 排序 (Sort) - 可选 ==========
    // 按时间戳排序事件，确保时序一致性
    if t.config.Output.EventsSorting {
        eventsChan, errc = t.eventsSorter.StartPipeline(ctx, eventsChan,
                                                        t.config.BlobPerfBufferSize)
        t.stats.Channels["sort"] = eventsChan
        errcList = append(errcList, errc)
    }

    // ========== 阶段3: 处理 (Process) ==========
    // 应用事件处理函数，提取和转换数据
    eventsChan, errc = t.processEvents(ctx, eventsChan)
    t.stats.Channels["process"] = eventsChan
    errcList = append(errcList, errc)

    // ========== 阶段4: 丰富 (Enrich) ==========
    // 添加容器元数据（名称、镜像、K8s 信息）
    if !t.config.NoContainersEnrich {
        eventsChan, errc = t.enrichContainerEvents(ctx, eventsChan)
        t.stats.Channels["enrich"] = eventsChan
        errcList = append(errcList, errc)
    }

    // ========== 阶段5: 派生 (Derive) ==========
    // 从基础事件派生高级事件
    eventsChan, errc = t.deriveEvents(ctx, eventsChan)
    t.stats.Channels["derive"] = eventsChan
    errcList = append(errcList, errc)

    // ========== 阶段6: 引擎 (Engine) ==========
    // 运行安全检测签名，生成告警
    if t.config.EngineConfig.Mode == engine.ModeSingleBinary {
        eventsChan, errc = t.engineEvents(ctx, eventsChan)
        t.stats.Channels["engine"] = eventsChan
        errcList = append(errcList, errc)
    }

    // ========== 阶段7: 输出 (Sink) ==========
    // 将事件发送到输出目标
    errc = t.sinkEvents(ctx, eventsChan)
    errcList = append(errcList, errc)

    // 通知初始化完成
    close(initialized)

    // 等待所有阶段完成或出错
    if err := waitForPipeline(errcList...); err != nil {
        logger.Errorw("Pipeline error", "error", err)
    }

    // 关闭 done channel，通知所有等待者
    close(t.done)
}
```

### 1.3 流水线特性

| 特性 | 说明 | 优势 |
|------|------|------|
| **管道模式** | 每阶段输出 channel 作为下阶段输入 | 解耦各阶段，易于扩展 |
| **并发处理** | 每阶段独立 goroutine | 最大化吞吐量 |
| **可配置** | 排序/丰富/引擎等阶段可选 | 灵活适配不同场景 |
| **错误处理** | 每阶段返回错误 channel | 统一汇总，不阻塞流水线 |
| **背压支持** | Channel 有缓冲区限制 | 防止内存溢出 |

---

## 2. 事件定义系统

### 2.1 事件 ID 体系 - [pkg/events/core.go](pkg/events/core.go#L13)

```go
const (
    // 特殊 ID
    All            ID = 0xfffffff - 1  // 所有事件
    Undefined      ID = 0xfffffff - 2  // 未定义
    Sys32Undefined ID = 0xfffffff - 3  // 32位系统调用未定义
    Unsupported    ID = 9000           // 不支持的事件
    MaxBuiltinID   ID = 10000 - 1      // 最大内置 ID
)

type ID int32

// ========== 事件 ID 范围划分 ==========
const (
    // 700-999: 网络基础事件
    NetPacketBase      ID = 700
    NetPacketRaw       ID = 701
    NetPacketIPBase    ID = 702
    NetPacketTCPBase   ID = 703
    NetPacketUDPBase   ID = 704
    NetPacketICMPBase  ID = 705
    NetPacketDNSBase   ID = 708
    NetPacketHTTPBase  ID = 709
    NetPacketCapture   ID = 710
    NetPacketFlow      ID = 711
    MaxNetID           ID = 712

    // 712+: 系统事件
    SysEnter            ID = 712
    SysExit             ID = 713
    SchedProcessFork    ID = 714
    SchedProcessExec    ID = 715
    SchedProcessExit    ID = 716

    // LSM 安全事件
    SecurityBprmCheck     ID = 758
    SecurityFileOpen      ID = 759
    SecurityInodeUnlink   ID = 760
    SecuritySocketCreate  ID = 761
    SecuritySocketConnect ID = 763

    // ... 400+ 事件定义
)
```

### 2.2 事件定义结构 - [pkg/events/definition.go](pkg/events/definition.go)

每个事件都有完整的元数据定义：

```go
// 示例：security_file_open 事件定义
events.Core.DefineEvent(
    events.SecurityFileOpen,
    events.Definition{
        ID:      events.SecurityFileOpen,
        Name:    "security_file_open",
        Version: 1,
        Fields: []trace.ArgMeta{
            {Type: "const char*", Name: "pathname"},
            {Type: "int", Name: "flags"},
            {Type: "dev_t", Name: "dev"},
            {Type: "unsigned long", Name: "inode"},
            {Type: "u64", Name: "ctime"},
        },
        Sets: []string{"lsm_hooks", "fs", "fs_file_ops"},
        Params: []trace.ArgMeta{
            {Type: "const char*", Name: "pathname"},
            {Type: "int", Name: "flags"},
            {Type: "dev_t", Name: "dev"},
            {Type: "unsigned long", Name: "inode"},
        },
        Dependencies: events.NewDependencies(
            events.SecurityInodeUnlink.GetID(),
        ),
        Category: events.FsActivity,
    },
)
```

### 2.3 事件分类

```go
// pkg/events/definition_group.go
const (
    SystemActivity   Category = "system"    // 系统活动
    ProcessActivity  Category = "process"   // 进程活动
    FsActivity       Category = "fs"        // 文件系统活动
    NetworkActivity  Category = "network"   // 网络活动
    SecurityAlert    Category = "security"  // 安全告警
)
```

---

## 3. 流水线各阶段详解

### 阶段1: 解码 (Decode)

#### 核心实现 - [pkg/ebpf/events_pipeline.go:153](pkg/ebpf/events_pipeline.go#L153)

```go
func (t *Tracee) decodeEvents(ctx context.Context,
                               sourceChan <-chan []byte) (
    <-chan *trace.Event,
    <-chan error,
) {
    out := make(chan *trace.Event, t.config.PipelineChannelSize)
    errc := make(chan error, 1)

    go func() {
        defer close(out)
        defer close(errc)

        for {
            select {
            case <-ctx.Done():
                return

            case rawEvent := <-sourceChan:
                // ★ 从对象池获取事件对象（性能优化）
                ebpfEvent := t.eventsPool.Get().(*trace.Event)

                // ★ 解码原始字节到事件结构
                err := bufferdecoder.DecodeEvent(rawEvent, ebpfEvent,
                                                  t.dataTypeDecoder)
                if err != nil {
                    t.stats.EventsFiltered.Increment()
                    t.eventsPool.Put(ebpfEvent)  // 放回池
                    continue
                }

                // ★ 应用策略过滤
                if !t.matchPolicies(ebpfEvent) {
                    t.stats.EventsFiltered.Increment()
                    t.eventsPool.Put(ebpfEvent)
                    continue
                }

                // ★ 发送到下一阶段
                select {
                case out <- ebpfEvent:
                case <-ctx.Done():
                    return
                }
            }
        }
    }()

    return out, errc
}
```

**关键点**：
- 使用对象池减少内存分配
- 二进制协议解码（详见 [第4节](#4-事件解码机制)）
- 早期策略过滤（减少后续处理开销）

---

### 阶段2: 排序 (Sort) - 可选

#### 为什么需要排序？

```
问题：多核 CPU 上 eBPF 事件可能乱序

CPU 0: [Event A @100ms] ─┐
CPU 1: [Event B @99ms]  ─┤──▶ Perf Buffer ──▶ 用户空间
CPU 2: [Event C @101ms] ─┘                     B, A, C (乱序！)

解决：使用时间窗口排序器

时间窗口:    [95ms ─────── 105ms]
             ↓ 缓存事件
             ↓ 按时间戳排序
             ↓ 窗口滑动后输出
             ▼
输出:        B @99ms, A @100ms, C @101ms ✓
```

#### 实现 - [pkg/events/sorting/chronological_sorter.go](pkg/events/sorting/chronological_sorter.go)

```go
type EventsChronologicalSorter struct {
    eventWindow   []*trace.Event  // 事件窗口
    windowSize    time.Duration   // 窗口大小
    lastTimestamp time.Time       // 最后时间戳
}

func (s *EventsChronologicalSorter) StartPipeline(
    ctx context.Context,
    in <-chan *trace.Event,
    windowSize int,
) (<-chan *trace.Event, <-chan error) {
    out := make(chan *trace.Event, windowSize)
    errc := make(chan error, 1)

    go func() {
        defer close(out)
        defer close(errc)

        for {
            select {
            case <-ctx.Done():
                // 排空窗口
                s.flushWindow(out)
                return

            case event := <-in:
                if event == nil {
                    continue
                }

                // 添加到窗口
                s.eventWindow = append(s.eventWindow, event)

                // 窗口满或超时则排序输出
                if len(s.eventWindow) >= windowSize ||
                   time.Since(s.lastTimestamp) > s.windowSize {
                    s.sortAndFlush(out)
                }
            }
        }
    }()

    return out, errc
}

func (s *EventsChronologicalSorter) sortAndFlush(out chan<- *trace.Event) {
    // 按时间戳排序
    sort.Slice(s.eventWindow, func(i, j int) bool {
        return s.eventWindow[i].Timestamp < s.eventWindow[j].Timestamp
    })

    // 输出排序后的事件
    for _, event := range s.eventWindow {
        out <- event
    }

    // 清空窗口
    s.eventWindow = s.eventWindow[:0]
    s.lastTimestamp = time.Now()
}
```

**权衡**：
- ✅ 优点：保证事件顺序，便于关联分析
- ❌ 缺点：增加延迟（窗口大小）、内存占用

---

### 阶段3: 处理 (Process)

#### 核心功能

```go
// pkg/ebpf/events_pipeline.go:220
func (t *Tracee) processEvents(ctx context.Context,
                                in <-chan *trace.Event) (
    <-chan *trace.Event,
    <-chan error,
) {
    out := make(chan *trace.Event, t.config.PipelineChannelSize)
    errc := make(chan error, 1)

    go func() {
        defer close(out)
        defer close(errc)

        for {
            select {
            case <-ctx.Done():
                return

            case event := <-in:
                if event == nil {
                    continue
                }

                // ★ 执行事件特定的处理器
                if processors, exists := t.eventProcessor[event.EventID]; exists {
                    for _, processor := range processors {
                        if err := processor(event); err != nil {
                            logger.Warnw("Event processor failed",
                                "event", event.EventID,
                                "error", err)
                        }
                    }
                }

                // ★ 更新进程树
                if t.processTree != nil {
                    t.processTree.FeedEvent(event)
                }

                // ★ 更新 DNS 缓存
                if t.dnsCache != nil && event.EventID == events.NetPacketDNS {
                    t.dnsCache.Add(event)
                }

                // 发送到下一阶段
                out <- event
            }
        }
    }()

    return out, errc
}
```

#### 事件处理器注册

```go
// pkg/ebpf/processor.go
func (t *Tracee) RegisterEventProcessor(
    id events.ID,
    proc func(*trace.Event) error,
) {
    if t.eventProcessor == nil {
        t.eventProcessor = make(map[events.ID][]func(*trace.Event)error)
    }
    t.eventProcessor[id] = append(t.eventProcessor[id], proc)
}

// 示例：注册 execve 处理器
t.RegisterEventProcessor(events.SchedProcessExec, func(evt *trace.Event) error {
    // 提取命令行参数
    cmdline := evt.Args[0].Value.(string)
    logger.Infow("Process executed", "cmdline", cmdline)
    return nil
})
```

---

### 阶段4: 丰富 (Enrich)

#### 容器元数据丰富 - [pkg/ebpf/events_enrich.go](pkg/ebpf/events_enrich.go)

```go
func (t *Tracee) enrichContainerEvents(ctx context.Context,
                                        in <-chan *trace.Event) (
    <-chan *trace.Event,
    <-chan error,
) {
    out := make(chan *trace.Event, t.config.PipelineChannelSize)
    errc := make(chan error, 1)

    go func() {
        defer close(out)
        defer close(errc)

        for {
            select {
            case <-ctx.Done():
                return

            case event := <-in:
                if event == nil {
                    continue
                }

                // ★ 获取容器信息
                if event.Container.ID != "" {
                    container, err := t.containers.GetContainer(event.Container.ID)
                    if err == nil {
                        // 丰富容器元数据
                        event.Container.Name = container.Name
                        event.Container.Image = container.Image
                        event.Container.ImageDigest = container.ImageDigest

                        // 丰富 Kubernetes 信息
                        if !container.Pod.Sandbox {
                            event.Kubernetes.PodName = container.Pod.Name
                            event.Kubernetes.PodNamespace = container.Pod.Namespace
                            event.Kubernetes.PodUID = container.Pod.UID
                        }
                    }
                }

                out <- event
            }
        }
    }()

    return out, errc
}
```

**丰富内容**：

| 类型 | 字段 | 来源 |
|------|------|------|
| 容器 | `Container.Name` | Docker/containerd API |
| 容器 | `Container.Image` | 容器运行时 |
| 容器 | `Container.ImageDigest` | 镜像清单 |
| K8s | `Kubernetes.PodName` | CRI API |
| K8s | `Kubernetes.PodNamespace` | Pod 标签 |
| K8s | `Kubernetes.PodUID` | Pod UID |

---

### 阶段5: 派生 (Derive)

详见 [第5节：事件派生系统](#5-事件派生系统)

---

### 阶段6: 引擎 (Engine)

#### 签名检测流程

```go
// pkg/ebpf/signature_engine.go
func (t *Tracee) engineEvents(ctx context.Context,
                               in <-chan *trace.Event) (
    <-chan *trace.Event,
    <-chan error,
) {
    out := make(chan *trace.Event, t.config.PipelineChannelSize)
    errc := make(chan error, 1)

    go func() {
        defer close(out)
        defer close(errc)

        for {
            select {
            case <-ctx.Done():
                return

            case event := <-in:
                if event == nil {
                    continue
                }

                // ★ 提交事件到签名引擎
                if t.sigEngine != nil {
                    inputs := []detect.SignatureEventSelector{
                        {
                            Source: event.EventName,
                            Name:   event.EventName,
                        },
                    }

                    // 匹配所有签名
                    err := t.sigEngine.OnEvent(event)
                    if err != nil {
                        logger.Warnw("Signature engine error", "error", err)
                    }
                }

                // ★ 如果产生 Finding，也发送到输出
                out <- event
            }
        }
    }()

    return out, errc
}
```

**签名引擎工作流**：

```
Event ──▶ Engine.OnEvent()
            │
            ├──▶ Signature 1 (匹配?) ─▶ Generate Finding
            ├──▶ Signature 2 (匹配?) ─▶ Generate Finding
            └──▶ Signature N (匹配?) ─▶ Generate Finding
```

---

### 阶段7: 输出 (Sink)

#### 多输出支持

```go
// pkg/ebpf/events_pipeline.go:380
func (t *Tracee) sinkEvents(ctx context.Context,
                             in <-chan *trace.Event) <-chan error {
    errc := make(chan error, 1)

    go func() {
        defer close(errc)

        for {
            select {
            case <-ctx.Done():
                return

            case event := <-in:
                if event == nil {
                    continue
                }

                // ★ 发送到所有订阅的流
                t.streamsManager.Publish(event)

                // 统计
                t.stats.EventCount.Increment()
            }
        }
    }()

    return errc
}
```

**输出目标**：

| 类型 | 配置 | 用途 |
|------|------|------|
| **stdout** | `-o table` | 终端表格输出 |
| **JSON** | `-o json` | 结构化日志 |
| **Webhook** | `-o webhook:http://...` | 发送到外部服务 |
| **gRPC** | `--server grpc` | 流式 API |
| **文件** | `-o json:file=/tmp/events.json` | 持久化存储 |

---

## 4. 事件解码机制

### 4.1 二进制协议格式

```
┌─────────────────────────────────────────────────────────┐
│              eBPF 事件二进制格式（Perf Buffer）           │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  Header (固定长度)                                        │
│  ┌──────────────────────────────────────────────────┐  │
│  │ Timestamp (u64)    │ 8 bytes                      │  │
│  │ ThreadStartTime(u64)│ 8 bytes                     │  │
│  │ ProcessorId (u32)  │ 4 bytes                      │  │
│  │ ProcessId (u32)    │ 4 bytes                      │  │
│  │ ThreadId (u32)     │ 4 bytes                      │  │
│  │ EventID (u32)      │ 4 bytes                      │  │
│  │ ReturnValue (s64)  │ 8 bytes                      │  │
│  └──────────────────────────────────────────────────┘  │
│                                                          │
│  Context (可变长度)                                      │
│  ┌──────────────────────────────────────────────────┐  │
│  │ HostProcessId (u32)      │ 4 bytes               │  │
│  │ HostThreadId (u32)       │ 4 bytes               │  │
│  │ ParentProcessId (u32)    │ 4 bytes               │  │
│  │ ProcessName (char[16])   │ 16 bytes              │  │
│  │ ContainerId (char[16])   │ 16 bytes              │  │
│  └──────────────────────────────────────────────────┘  │
│                                                          │
│  Arguments Buffer (可变长度)                             │
│  ┌──────────────────────────────────────────────────┐  │
│  │ Arg0: [Type|Size|Data...]                        │  │
│  │ Arg1: [Type|Size|Data...]                        │  │
│  │ ...                                               │  │
│  │ ArgN: [Type|Size|Data...]                        │  │
│  └──────────────────────────────────────────────────┘  │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

### 4.2 解码器实现 - [pkg/bufferdecoder/decoder.go](pkg/bufferdecoder/decoder.go)

```go
// 核心解码函数
func DecodeEvent(rawEvent []byte,
                 event *trace.Event,
                 decoder TypeDecoder) error {
    reader := bytes.NewReader(rawEvent)

    // ========== 解码 Header ==========
    binary.Read(reader, binary.LittleEndian, &event.Timestamp)
    binary.Read(reader, binary.LittleEndian, &event.ThreadStartTime)
    binary.Read(reader, binary.LittleEndian, &event.ProcessorID)
    binary.Read(reader, binary.LittleEndian, &event.ProcessID)
    binary.Read(reader, binary.LittleEndian, &event.ThreadID)
    binary.Read(reader, binary.LittleEndian, &event.EventID)
    binary.Read(reader, binary.LittleEndian, &event.ReturnValue)

    // ========== 解码 Context ==========
    binary.Read(reader, binary.LittleEndian, &event.HostProcessID)
    binary.Read(reader, binary.LittleEndian, &event.HostThreadID)
    binary.Read(reader, binary.LittleEndian, &event.ParentProcessID)

    // 读取进程名（null-terminated）
    procName := make([]byte, 16)
    reader.Read(procName)
    event.ProcessName = strings.TrimRight(string(procName), "\x00")

    // 读取容器 ID
    containerID := make([]byte, 16)
    reader.Read(containerID)
    event.Container.ID = strings.TrimRight(string(containerID), "\x00")

    // ========== 解码参数 ==========
    argNum := 0
    for reader.Len() > 0 {
        arg, err := decodeArgument(reader, decoder)
        if err != nil {
            return err
        }
        event.Args = append(event.Args, arg)
        argNum++
    }

    return nil
}

// 解码单个参数
func decodeArgument(reader *bytes.Reader,
                    decoder TypeDecoder) (trace.Argument, error) {
    var argType uint8
    var argSize uint32

    // 读取类型和大小
    binary.Read(reader, binary.LittleEndian, &argType)
    binary.Read(reader, binary.LittleEndian, &argSize)

    // 根据类型解码数据
    switch argType {
    case ARG_TYPE_INT:
        var value int32
        binary.Read(reader, binary.LittleEndian, &value)
        return trace.Argument{Type: "int", Value: value}, nil

    case ARG_TYPE_STR:
        data := make([]byte, argSize)
        reader.Read(data)
        return trace.Argument{
            Type:  "const char*",
            Value: string(data),
        }, nil

    case ARG_TYPE_SOCKADDR:
        // 解码 sockaddr 结构
        data := make([]byte, argSize)
        reader.Read(data)
        sockAddr := decoder.DecodeSockAddr(data)
        return trace.Argument{Type: "sockaddr", Value: sockAddr}, nil

    // ... 更多类型
    }

    return trace.Argument{}, fmt.Errorf("unknown arg type: %d", argType)
}
```

### 4.3 参数类型系统

| eBPF 类型 | Go 类型 | 示例值 |
|-----------|---------|--------|
| `ARG_TYPE_INT` | `int32` | `42` |
| `ARG_TYPE_UINT` | `uint32` | `1000` |
| `ARG_TYPE_LONG` | `int64` | `9223372036854775807` |
| `ARG_TYPE_STR` | `string` | `"/etc/passwd"` |
| `ARG_TYPE_SOCKADDR` | `trace.SockAddr` | `{Family: AF_INET, IP: "192.168.1.1"}` |
| `ARG_TYPE_BYTES` | `[]byte` | `[0x48, 0x65, 0x6c, 0x6c, 0x6f]` |

---

## 5. 事件派生系统

### 5.1 什么是派生事件？

```
基础事件 ──▶ 逻辑处理 ──▶ 派生事件

示例1: DNS 查询和响应
  NetPacketDNSBase (请求)  ─┐
                            ├─▶ 关联处理 ─▶ NetPacketDNS (完整会话)
  NetPacketDNSBase (响应)  ─┘

示例2: 进程执行链
  SchedProcessFork   ─┐
  SchedProcessExec   ─┼─▶ 进程树构建 ─▶ ProcessLineage (进程家族树)
  SchedProcessExit   ─┘
```

### 5.2 派生表定义 - [pkg/events/derive/derive.go](pkg/events/derive/derive.go)

```go
type Table struct {
    derivations map[events.ID]Deriver
}

type Deriver interface {
    // 从源事件派生新事件
    Derive(sourceEvent *trace.Event) ([]*trace.Event, error)

    // 需要哪些源事件
    GetDependencies() []events.ID
}

// 注册派生器
func (t *Table) Register(targetID events.ID, deriver Deriver) {
    t.derivations[targetID] = deriver
}
```

### 5.3 派生流程

```go
// pkg/ebpf/events_pipeline.go:280
func (t *Tracee) deriveEvents(ctx context.Context,
                               in <-chan *trace.Event) (
    <-chan *trace.Event,
    <-chan error,
) {
    out := make(chan *trace.Event, t.config.PipelineChannelSize)
    errc := make(chan error, 1)

    go func() {
        defer close(out)
        defer close(errc)

        for {
            select {
            case <-ctx.Done():
                return

            case event := <-in:
                if event == nil {
                    continue
                }

                // ★ 先发送原始事件
                out <- event

                // ★ 尝试派生新事件
                derivedEvents := t.eventDerivations.Derive(event)
                for _, derivedEvent := range derivedEvents {
                    // 发送派生事件
                    out <- derivedEvent
                }
            }
        }
    }()

    return out, errc
}
```

### 5.4 DNS 派生示例

```go
// pkg/events/derive/net_packet_dns.go
type DNSDeriver struct {
    cache map[uint16]*pendingRequest  // DNS 事务 ID -> 请求
}

type pendingRequest struct {
    queryEvent *trace.Event
    timestamp  time.Time
}

func (d *DNSDeriver) Derive(event *trace.Event) ([]*trace.Event, error) {
    if event.EventID != events.NetPacketDNSBase {
        return nil, nil
    }

    // 提取 DNS 数据
    dnsData := event.Args[0].Value.(DNSData)
    txID := dnsData.TransactionID

    if dnsData.QueryResponse == DNS_QUERY {
        // 这是查询，缓存起来
        d.cache[txID] = &pendingRequest{
            queryEvent: event,
            timestamp:  time.Now(),
        }
        return nil, nil
    }

    // 这是响应，查找对应的查询
    if req, exists := d.cache[txID]; exists {
        // ★ 创建派生事件：完整的 DNS 会话
        derivedEvent := &trace.Event{
            EventID:   events.NetPacketDNS,
            EventName: "net_packet_dns",
            Timestamp: event.Timestamp,
            Args: []trace.Argument{
                {Name: "query", Value: req.queryEvent.Args[0]},
                {Name: "response", Value: event.Args[0]},
                {Name: "latency_ms", Value:
                    time.Since(req.timestamp).Milliseconds()},
            },
        }

        // 清理缓存
        delete(d.cache, txID)

        return []*trace.Event{derivedEvent}, nil
    }

    return nil, nil
}
```

---

## 6. 实践练习

### 练习 1：跟踪流水线各阶段

**目标**：观察事件在流水线中的流转

```go
// 在 pkg/ebpf/events_pipeline.go 添加日志

func (t *Tracee) handleEvents(ctx context.Context, ...) {
    // 在每个阶段后添加计数器
    var (
        decodeCount  atomic.Uint64
        sortCount    atomic.Uint64
        processCount atomic.Uint64
        enrichCount  atomic.Uint64
        deriveCount  atomic.Uint64
        engineCount  atomic.Uint64
        sinkCount    atomic.Uint64
    )

    // 启动监控 goroutine
    go func() {
        ticker := time.NewTicker(5 * time.Second)
        defer ticker.Stop()

        for {
            select {
            case <-ctx.Done():
                return
            case <-ticker.C:
                logger.Infow("Pipeline stats",
                    "decode", decodeCount.Load(),
                    "sort", sortCount.Load(),
                    "process", processCount.Load(),
                    "enrich", enrichCount.Load(),
                    "derive", deriveCount.Load(),
                    "engine", engineCount.Load(),
                    "sink", sinkCount.Load(),
                )
            }
        }
    }()

    // ... 在每个阶段的 goroutine 中递增计数器
}
```

### 练习 2：自定义事件处理器

**目标**：注册一个处理器，统计每个进程的系统调用次数

```go
// 在初始化时注册处理器
type SyscallStats struct {
    mu     sync.Mutex
    counts map[int32]map[string]int  // pid -> syscall name -> count
}

func (s *SyscallStats) Process(evt *trace.Event) error {
    if evt.EventID != events.SysEnter {
        return nil
    }

    s.mu.Lock()
    defer s.mu.Unlock()

    if _, exists := s.counts[evt.ProcessID]; !exists {
        s.counts[evt.ProcessID] = make(map[string]int)
    }

    syscallName := evt.Args[0].Value.(string)
    s.counts[evt.ProcessID][syscallName]++

    return nil
}

// 在 Tracee 初始化时
stats := &SyscallStats{counts: make(map[int32]map[string]int)}
t.RegisterEventProcessor(events.SysEnter, stats.Process)
```

### 练习 3：实现简单派生器

**目标**：从 `security_file_open` 事件派生 "可疑文件访问" 事件

```go
type SuspiciousFileAccessDeriver struct {
    suspiciousPaths []string
}

func NewSuspiciousFileAccessDeriver() *SuspiciousFileAccessDeriver {
    return &SuspiciousFileAccessDeriver{
        suspiciousPaths: []string{
            "/etc/shadow",
            "/root/.ssh/id_rsa",
            "/var/log/auth.log",
        },
    }
}

func (d *SuspiciousFileAccessDeriver) Derive(
    event *trace.Event,
) ([]*trace.Event, error) {
    if event.EventID != events.SecurityFileOpen {
        return nil, nil
    }

    // 提取文件路径
    pathname := event.Args[0].Value.(string)

    // 检查是否为可疑路径
    for _, suspPath := range d.suspiciousPaths {
        if strings.HasPrefix(pathname, suspPath) {
            // 创建派生事件
            derived := &trace.Event{
                EventID:       events.MaxBuiltinID + 1,  // 自定义 ID
                EventName:     "suspicious_file_access",
                Timestamp:     event.Timestamp,
                ProcessID:     event.ProcessID,
                ProcessName:   event.ProcessName,
                Args: []trace.Argument{
                    {Name: "pathname", Value: pathname},
                    {Name: "process", Value: event.ProcessName},
                    {Name: "severity", Value: "high"},
                },
            }
            return []*trace.Event{derived}, nil
        }
    }

    return nil, nil
}
```

### 练习 4：观察事件顺序

**实验**：比较启用和禁用排序的区别

```bash
# 禁用排序（默认）
sudo ./dist/tracee -e execve -o json | head -20 > no-sort.json

# 启用排序
sudo ./dist/tracee -e execve -o json --events-sorting | head -20 > sorted.json

# 分析时间戳顺序
cat no-sort.json | jq '.timestamp' | sort -n
cat sorted.json | jq '.timestamp' | sort -n
```

---

## 7. 总结与下一步

### 本阶段学到的

- ✅ 7 阶段流水线架构和数据流
- ✅ 事件定义系统和 ID 分类
- ✅ 二进制协议解码机制
- ✅ 事件派生和关联逻辑
- ✅ 容器元数据丰富过程

### 下一步学习

继续第三阶段：**[eBPF 内核侧实现](03-ebpf-implementation.md)**

重点内容：
- eBPF C 程序结构
- 系统调用拦截机制
- LSM Hook 使用
- Perf Buffer 数据提交
- BPF Maps 设计

---

**上一篇**：[第一阶段：架构概览](01-architecture-overview.md) | **下一篇**：[第三阶段：eBPF 实现](03-ebpf-implementation.md)
