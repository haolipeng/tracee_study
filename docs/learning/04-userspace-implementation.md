# Tracee 源代码学习指南 - 第四阶段：Go 用户空间实现

> **学习目标**：深入理解 Go 用户空间的核心组件实现
> **预计时间**：3-5 天
> **前置知识**：完成前三阶段学习，熟悉 Go 并发编程

---

## 📋 目录

1. [用户空间架构概览](#1-用户空间架构概览)
2. [事件解码器详解](#2-事件解码器详解)
3. [进程树管理](#3-进程树管理)
4. [容器信息获取](#4-容器信息获取)
5. [DNS 缓存机制](#5-dns-缓存机制)
6. [符号表管理](#6-符号表管理)
7. [实践练习](#7-实践练习)

---

## 1. 用户空间架构概览

### 1.1 核心组件关系

```
┌─────────────────────────────────────────────────────────────────┐
│                  Tracee 用户空间组件架构                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  数据输入层                                                       │
│  ┌────────────────────────────────────────────────────────────┐│
│  │  Perf Buffer Reader                                         ││
│  │  • eventsPerfMap    - 主事件流                              ││
│  │  • fileWrPerfMap    - 文件写入捕获                          ││
│  │  • netCapPerfMap    - 网络捕获                              ││
│  │  • bpfLogsPerfMap   - eBPF 日志                             ││
│  └────────────┬────────────────────────────────────────────────┘│
│               │                                                  │
│               ▼                                                  │
│  解码转换层                                                       │
│  ┌────────────────────────────────────────────────────────────┐│
│  │  bufferdecoder.EbpfDecoder                                  ││
│  │  • 二进制 → trace.Event                                     ││
│  │  • 类型转换 (TypeDecoder)                                   ││
│  │  • 参数解析                                                  ││
│  └────────────┬────────────────────────────────────────────────┘│
│               │                                                  │
│               ▼                                                  │
│  数据增强层                                                       │
│  ┌────────────────────────────────────────────────────────────┐│
│  │  ┌────────────────┐  ┌────────────────┐  ┌──────────────┐ ││
│  │  │  ProcessTree   │  │  Containers    │  │  DNSCache    │ ││
│  │  │  进程树追踪     │  │  容器元数据     │  │  DNS解析     │ ││
│  │  └────────────────┘  └────────────────┘  └──────────────┘ ││
│  │  ┌────────────────┐  ┌────────────────┐                    ││
│  │  │  Symbols       │  │  CGroups       │                    ││
│  │  │  符号表管理     │  │  Cgroup信息    │                    ││
│  │  └────────────────┘  └────────────────┘                    ││
│  └────────────┬────────────────────────────────────────────────┘│
│               │                                                  │
│               ▼                                                  │
│  存储缓存层                                                       │
│  ┌────────────────────────────────────────────────────────────┐│
│  │  • LRU Cache (hashicorp/golang-lru)                        ││
│  │  • Bucket Cache (PID in mntns)                             ││
│  │  • Digest Cache (文件哈希)                                  ││
│  │  • Object Pools (sync.Pool)                                ││
│  └─────────────────────────────────────────────────────────────┘│
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### 1.2 核心包职责

| 包名 | 职责 | 核心文件 | 代码行数 |
|------|------|---------|---------|
| **bufferdecoder** | 事件解码 | `decoder.go` | ~600 |
| **proctree** | 进程树管理 | `proctree.go` | ~500 |
| **containers** | 容器信息 | `containers.go` | ~600 |
| **dnscache** | DNS 缓存 | `dnscache.go` | ~300 |
| **symbols** | 符号表 | `symbols.go` | ~400 |
| **metrics** | 统计指标 | `stats.go` | ~300 |
| **streams** | 事件流 | `streams.go` | ~200 |

---

## 2. 事件解码器详解

### 2.1 解码器架构

```
原始字节流 (Perf Buffer)
         │
         ▼
┌──────────────────────────────────────────────────────────┐
│           EbpfDecoder (bufferdecoder.EbpfDecoder)         │
├──────────────────────────────────────────────────────────┤
│                                                           │
│  1. 解码 Context (上下文信息)                              │
│     ┌─────────────────────────────────────────────────┐ │
│     │ • Timestamp (u64)      - 事件时间戳              │ │
│     │ • ProcessID (u32)      - 进程 ID                │ │
│     │ • ThreadID (u32)       - 线程 ID                │ │
│     │ • ProcessName (str)    - 进程名                 │ │
│     │ • Container.ID (str)   - 容器 ID                │ │
│     │ • UID/GID (u32)        - 用户/组 ID             │ │
│     └─────────────────────────────────────────────────┘ │
│                                                           │
│  2. 解码 Arguments (参数列表)                             │
│     ┌─────────────────────────────────────────────────┐ │
│     │ For each argument:                              │ │
│     │   • Type (u8)      - 参数类型                    │ │
│     │   • Size (u32)     - 数据大小                    │ │
│     │   • Data ([]byte)  - 原始数据                    │ │
│     │   ↓                                             │ │
│     │ TypeDecoder.Decode(type, data)                  │ │
│     │   ↓                                             │ │
│     │ Argument{Name, Type, Value}                     │ │
│     └─────────────────────────────────────────────────┘ │
│                                                           │
│  3. 输出 trace.Event                                      │
│     ┌─────────────────────────────────────────────────┐ │
│     │ type Event struct {                             │ │
│     │     EventID       events.ID                     │ │
│     │     Timestamp     uint64                        │ │
│     │     ProcessID     int32                         │ │
│     │     ThreadID      int32                         │ │
│     │     ProcessName   string                        │ │
│     │     Container     Container                     │ │
│     │     Args          []Argument                    │ │
│     │     ...                                         │ │
│     │ }                                               │ │
│     └─────────────────────────────────────────────────┘ │
│                                                           │
└──────────────────────────────────────────────────────────┘
```

### 2.2 核心实现 - [pkg/bufferdecoder/decoder.go](pkg/bufferdecoder/decoder.go)

#### 解码器结构

```go
// EbpfDecoder 负责将 eBPF 程序发送的原始字节解码为 trace.Event
type EbpfDecoder struct {
    buffer      []byte      // 原始字节缓冲区
    cursor      int         // 当前读取位置
    typeDecoder TypeDecoder // 类型解码器
}

// TypeDecoder 定义如何将特定类型的数据转换为 Go 类型
// 索引: [数据类型][目标类型] -> 转换函数
type TypeDecoder []map[string]presentorFunc

type presentorFunc func(any) (any, error)
```

#### 主解码流程

```go
// New 创建解码器
func New(rawBuffer []byte, typeDecoder TypeDecoder) *EbpfDecoder {
    return &EbpfDecoder{
        buffer:      rawBuffer,
        cursor:      0,
        typeDecoder: typeDecoder,
    }
}

// DecodeContext 解码事件上下文
func (decoder *EbpfDecoder) DecodeContext(ctx *trace.Event) error {
    var err error

    // ========== 1. 解码时间戳 (u64) ==========
    ctx.Timestamp, err = decoder.DecodeUint64()
    if err != nil {
        return errfmt.WrapError(err)
    }

    // ========== 2. 解码线程启动时间 (u64) ==========
    ctx.ThreadStartTime, err = decoder.DecodeUint64()
    if err != nil {
        return errfmt.WrapError(err)
    }

    // ========== 3. 解码处理器 ID (u32) ==========
    ctx.ProcessorID, err = decoder.DecodeUint32()
    if err != nil {
        return errfmt.WrapError(err)
    }

    // ========== 4. 解码进程和线程 ID (u32 x2) ==========
    ctx.ProcessID, err = decoder.DecodeInt32()
    if err != nil {
        return errfmt.WrapError(err)
    }

    ctx.ThreadID, err = decoder.DecodeInt32()
    if err != nil {
        return errfmt.WrapError(err)
    }

    // ========== 5. 解码父进程 ID (u32) ==========
    ctx.ParentProcessID, err = decoder.DecodeInt32()
    if err != nil {
        return errfmt.WrapError(err)
    }

    // ========== 6. 解码进程名 (16 bytes null-terminated) ==========
    commBytes := make([]byte, 16)
    err = decoder.DecodeBytes(commBytes)
    if err != nil {
        return errfmt.WrapError(err)
    }
    ctx.ProcessName = string(bytes.TrimRight(commBytes, "\x00"))

    // ========== 7. 解码容器 ID (16 bytes) ==========
    containerIDBytes := make([]byte, 16)
    err = decoder.DecodeBytes(containerIDBytes)
    if err != nil {
        return errfmt.WrapError(err)
    }
    ctx.Container.ID = string(bytes.TrimRight(containerIDBytes, "\x00"))

    // ========== 8. 解码事件 ID (u32) ==========
    eventID, err := decoder.DecodeUint32()
    if err != nil {
        return errfmt.WrapError(err)
    }
    ctx.EventID = events.ID(eventID)

    // ========== 9. 解码返回值 (s64) ==========
    ctx.ReturnValue, err = decoder.DecodeInt64()
    if err != nil {
        return errfmt.WrapError(err)
    }

    // ... 解码其他上下文字段 (UID, GID, Cgroup ID 等)

    return nil
}
```

#### 参数解码

```go
// DecodeArgument 解码单个参数
func (decoder *EbpfDecoder) DecodeArgument() (trace.Argument, error) {
    var arg trace.Argument

    // ========== 1. 读取参数类型 (u8) ==========
    argType, err := decoder.DecodeUint8()
    if err != nil {
        return arg, err
    }

    // ========== 2. 读取参数大小 (u32) ==========
    argSize, err := decoder.DecodeUint32()
    if err != nil {
        return arg, err
    }

    // ========== 3. 根据类型解码数据 ==========
    switch data.ArgType(argType) {
    case data.INT_T:
        var value int32
        value, err = decoder.DecodeInt32()
        arg.Value = value
        arg.Type = "int"

    case data.STR_T:
        strBytes := make([]byte, argSize)
        err = decoder.DecodeBytes(strBytes)
        arg.Value = string(strBytes)
        arg.Type = "const char*"

    case data.SOCK_ADDR_T:
        var sockAddr trace.SockAddr
        err = decoder.DecodeSockAddr(&sockAddr)
        arg.Value = sockAddr
        arg.Type = "struct sockaddr*"

    case data.BYTES_T:
        bytesValue := make([]byte, argSize)
        err = decoder.DecodeBytes(bytesValue)
        arg.Value = bytesValue
        arg.Type = "bytes"

    // ... 更多类型处理
    }

    if err != nil {
        return arg, errfmt.WrapError(err)
    }

    return arg, nil
}
```

### 2.3 类型解码器 (TypeDecoder)

```go
// NewTypeDecoder 创建类型转换映射
func NewTypeDecoder() TypeDecoder {
    typeDecoder := TypeDecoder{
        // ========== 整数类型 ==========
        data.INT_T:  {},
        data.UINT_T: {},
        data.LONG_T: {},

        // ========== 时间类型 ==========
        data.ULONG_T: {
            "time.Time": func(a any) (any, error) {
                argVal, ok := a.(uint64)
                if !ok {
                    return nil, errfmt.Errorf("expected uint64, got %T", a)
                }
                // 转换 eBPF 时间戳为 Go time.Time
                return timeutil.NsSinceEpochToTime(
                    timeutil.BootToEpochNS(argVal),
                ), nil
            },
        },

        // ========== 字符串类型 ==========
        data.STR_T:     {},
        data.STR_ARR_T: {},

        // ========== 网络类型 ==========
        data.SOCK_ADDR_T: {},

        // ========== 字节数组 ==========
        data.BYTES_T: {},

        // ========== 凭证类型 ==========
        data.CRED_T: {},

        // ========== 布尔和浮点 ==========
        data.BOOL_T:    {},
        data.FLOAT_T:   {},
        data.FLOAT64_T: {},
    }

    return typeDecoder
}
```

### 2.4 性能优化

#### 零拷贝优化

```go
// 直接使用原始缓冲区，避免额外分配
func (decoder *EbpfDecoder) DecodeString(maxLen int) (string, error) {
    // 找到 null 终止符
    end := decoder.cursor
    for end < len(decoder.buffer) && end-decoder.cursor < maxLen {
        if decoder.buffer[end] == 0 {
            break
        }
        end++
    }

    // 直接从缓冲区切片创建字符串（零拷贝）
    str := string(decoder.buffer[decoder.cursor:end])
    decoder.cursor = end + 1 // 跳过 null 终止符

    return str, nil
}
```

#### 批量解码

```go
// 一次性解码多个参数
func (decoder *EbpfDecoder) DecodeAllArguments() ([]trace.Argument, error) {
    args := make([]trace.Argument, 0, 8) // 预分配常见大小

    for decoder.cursor < len(decoder.buffer) {
        arg, err := decoder.DecodeArgument()
        if err != nil {
            return args, err
        }
        args = append(args, arg)
    }

    return args, nil
}
```

---

## 3. 进程树管理

### 3.1 进程树设计原理

```
┌──────────────────────────────────────────────────────────────┐
│                    ProcessTree 数据结构                       │
├──────────────────────────────────────────────────────────────┤
│                                                               │
│  LRU 缓存 (主存储)                                            │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  processesLRU: hash → Process                        │   │
│  │  ┌────────────────────────────────────────────────┐  │   │
│  │  │ Hash: 12345                                     │  │   │
│  │  │ Process {                                       │  │   │
│  │  │   PID: 1234                                     │  │   │
│  │  │   Executable: /bin/bash                         │  │   │
│  │  │   Argv: ["bash", "-c", "ls"]                    │  │   │
│  │  │   Parent: 1000 (父进程hash)                     │  │   │
│  │  │   Threads: [12346, 12347] (线程hash列表)        │  │   │
│  │  │   Children: [12348, 12349] (子进程hash列表)     │  │   │
│  │  │ }                                               │  │   │
│  │  └────────────────────────────────────────────────┘  │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                               │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  threadsLRU: hash → Thread                           │   │
│  │  ┌────────────────────────────────────────────────┐  │   │
│  │  │ Hash: 12346                                     │  │   │
│  │  │ Thread {                                        │  │   │
│  │  │   TID: 1235                                     │  │   │
│  │  │   Leader: 12345 (线程组长hash)                  │  │   │
│  │  │   Parent: 1000                                  │  │   │
│  │  │ }                                               │  │   │
│  │  └────────────────────────────────────────────────┘  │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                               │
│  关系映射 (快速查询)                                          │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  processesThreads: process_hash → {thread_hash...}  │   │
│  │  processesChildren: process_hash → {child_hash...}  │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                               │
└──────────────────────────────────────────────────────────────┘
```

### 3.2 核心实现 - [pkg/proctree/proctree.go](pkg/proctree/proctree.go)

#### 进程树结构

```go
// ProcessTree 维护进程和线程的层次关系
type ProcessTree struct {
    // ========== 主存储 (LRU 缓存) ==========
    processesLRU *lru.Cache[uint32, *Process] // hash → process
    threadsLRU   *lru.Cache[uint32, *Thread]  // hash → thread

    // ========== 关系映射 ==========
    processesThreads  map[uint32]map[uint32]struct{} // process → threads
    processesChildren map[uint32]map[uint32]struct{} // process → children

    // ========== Procfs 支持 ==========
    procfsChan  chan int32      // 从 procfs 读取的 PID 队列
    procfsOnce  *sync.Once      // 初始化标志
    procfsQuery bool            // 是否查询 procfs

    // ========== 线程安全 ==========
    processesThreadsMtx  sync.RWMutex
    processesChildrenMtx sync.RWMutex

    // ========== 对象池 (性能优化) ==========
    forkFeedPool     *sync.Pool // Fork 事件池
    execFeedPool     *sync.Pool // Exec 事件池
    exitFeedPool     *sync.Pool // Exit 事件池
    taskInfoFeedPool *sync.Pool // TaskInfo 池
    fileInfoFeedPool *sync.Pool // FileInfo 池

    ctx context.Context
}

// Process 表示一个进程（线程组长）
type Process struct {
    PID        int32             // 进程 ID
    TID        int32             // 线程 ID (等于 PID)
    PPID       int32             // 父进程 ID
    Executable *FileInfo         // 可执行文件信息
    Interpreter *FileInfo        // 解释器信息 (如 python)
    Argv       []string          // 命令行参数
    Env        []string          // 环境变量
    UID        int32             // 用户 ID
    GID        int32             // 组 ID
    StartTime  time.Time         // 启动时间
}

// Thread 表示一个线程
type Thread struct {
    TID       int32    // 线程 ID
    Leader    uint32   // 线程组长 hash
    Parent    uint32   // 父进程 hash
    StartTime time.Time
}
```

#### 创建进程树

```go
func NewProcessTree(ctx context.Context, config ProcTreeConfig) (*ProcessTree, error) {
    procTree := &ProcessTree{
        processesThreads:  make(map[uint32]map[uint32]struct{}),
        processesChildren: make(map[uint32]map[uint32]struct{}),
        procfsChan:        make(chan int32, 1000),
        procfsOnce:        &sync.Once{},
        ctx:               ctx,
        procfsQuery:       config.ProcfsQuerying,
    }

    // ========== 创建 LRU 缓存 ==========
    var err error
    procTree.processesLRU, err = lru.NewWithEvict(
        config.ProcessCacheSize,
        procTree.onEvictProcess, // 驱逐回调
    )
    if err != nil {
        return nil, errfmt.WrapError(err)
    }

    procTree.threadsLRU, err = lru.NewWithEvict(
        config.ThreadCacheSize,
        procTree.onEvictThread,
    )
    if err != nil {
        return nil, errfmt.WrapError(err)
    }

    // ========== 初始化对象池 ==========
    procTree.forkFeedPool = &sync.Pool{
        New: func() any { return &ForkFeed{} },
    }
    procTree.execFeedPool = &sync.Pool{
        New: func() any { return &ExecFeed{} },
    }
    // ... 其他池

    // ========== 从 procfs 初始化 ==========
    if config.ProcfsInitialization {
        if err := procTree.initFromProcfs(); err != nil {
            logger.Warnw("Failed to initialize from procfs", "error", err)
        }
    }

    // ========== 启动 procfs 查询 goroutine ==========
    if config.ProcfsQuerying {
        go procTree.procfsWorker()
    }

    return procTree, nil
}
```

#### 喂养事件

```go
// FeedEvent 将事件信息添加到进程树
func (pt *ProcessTree) FeedEvent(event *trace.Event) {
    switch event.EventID {
    case events.SchedProcessFork:
        // 进程 fork
        pt.feedFork(event)

    case events.SchedProcessExec:
        // 进程执行
        pt.feedExec(event)

    case events.SchedProcessExit:
        // 进程退出
        pt.feedExit(event)

    // ... 其他事件类型
    }
}

// feedFork 处理 fork 事件
func (pt *ProcessTree) feedFork(event *trace.Event) {
    // ========== 从对象池获取 ForkFeed ==========
    feed := pt.forkFeedPool.Get().(*ForkFeed)
    defer pt.forkFeedPool.Put(feed)

    // ========== 提取 fork 信息 ==========
    feed.ParentPID = event.ProcessID
    feed.ParentTID = event.ThreadID
    feed.ChildPID = int32(event.Args[0].Value.(int32))
    feed.ChildTID = int32(event.Args[1].Value.(int32))

    // ========== 计算 hash ==========
    parentHash := pt.hashTaskID(feed.ParentPID, feed.ParentTID, 0)
    childHash := pt.hashTaskID(feed.ChildPID, feed.ChildTID, event.Timestamp)

    // ========== 创建子进程/线程 ==========
    if feed.ChildPID == feed.ChildTID {
        // 这是一个新进程 (fork)
        child := &Process{
            PID:       feed.ChildPID,
            TID:       feed.ChildTID,
            PPID:      feed.ParentPID,
            StartTime: time.Unix(0, int64(event.Timestamp)),
        }
        pt.processesLRU.Add(childHash, child)

        // 添加到父进程的 children 列表
        pt.addChild(parentHash, childHash)
    } else {
        // 这是一个新线程 (clone)
        thread := &Thread{
            TID:       feed.ChildTID,
            Leader:    pt.hashTaskID(feed.ChildPID, feed.ChildPID, 0),
            Parent:    parentHash,
            StartTime: time.Unix(0, int64(event.Timestamp)),
        }
        pt.threadsLRU.Add(childHash, thread)

        // 添加到线程组的 threads 列表
        leaderHash := thread.Leader
        pt.addThread(leaderHash, childHash)
    }
}

// feedExec 处理 exec 事件
func (pt *ProcessTree) feedExec(event *trace.Event) {
    feed := pt.execFeedPool.Get().(*ExecFeed)
    defer pt.execFeedPool.Put(feed)

    // ========== 提取 exec 信息 ==========
    feed.PID = event.ProcessID
    feed.TID = event.ThreadID
    feed.Binary = event.Args[0].Value.(string)       // 可执行文件路径
    feed.Argv = event.Args[1].Value.([]string)       // 命令行参数
    feed.Interpreter = event.Args[2].Value.(string)  // 解释器路径

    // ========== 更新进程信息 ==========
    hash := pt.hashTaskID(feed.PID, feed.TID, 0)
    proc, ok := pt.processesLRU.Get(hash)
    if !ok {
        // 进程不存在，可能需要从 procfs 加载
        if pt.procfsQuery {
            pt.procfsChan <- feed.PID
        }
        return
    }

    // 更新可执行文件信息
    proc.Executable = &FileInfo{
        Path: feed.Binary,
        // ... 其他字段
    }

    if feed.Interpreter != "" {
        proc.Interpreter = &FileInfo{
            Path: feed.Interpreter,
        }
    }

    proc.Argv = feed.Argv
}
```

### 3.3 Procfs 集成

```go
// initFromProcfs 从 /proc 初始化现有进程
func (pt *ProcessTree) initFromProcfs() error {
    // 遍历 /proc 目录
    entries, err := os.ReadDir("/proc")
    if err != nil {
        return err
    }

    for _, entry := range entries {
        // 跳过非数字目录
        if !entry.IsDir() {
            continue
        }

        pidStr := entry.Name()
        pid, err := strconv.Atoi(pidStr)
        if err != nil {
            continue // 不是进程目录
        }

        // 读取进程信息
        proc, err := pt.readProcessFromProcfs(int32(pid))
        if err != nil {
            continue // 进程可能已退出
        }

        // 添加到进程树
        hash := pt.hashTaskID(proc.PID, proc.TID, 0)
        pt.processesLRU.Add(hash, proc)
    }

    return nil
}

// readProcessFromProcfs 从 procfs 读取进程信息
func (pt *ProcessTree) readProcessFromProcfs(pid int32) (*Process, error) {
    proc := &Process{PID: pid, TID: pid}

    // ========== 读取 /proc/[pid]/stat ==========
    statPath := fmt.Sprintf("/proc/%d/stat", pid)
    statData, err := os.ReadFile(statPath)
    if err != nil {
        return nil, err
    }

    // 解析 stat 数据
    fields := strings.Fields(string(statData))
    if len(fields) < 5 {
        return nil, errors.New("invalid stat format")
    }

    proc.PPID, _ = strconv.ParseInt(fields[3], 10, 32)
    // ... 解析更多字段

    // ========== 读取 /proc/[pid]/cmdline ==========
    cmdlinePath := fmt.Sprintf("/proc/%d/cmdline", pid)
    cmdlineData, err := os.ReadFile(cmdlinePath)
    if err == nil {
        proc.Argv = strings.Split(string(cmdlineData), "\x00")
    }

    // ========== 读取 /proc/[pid]/exe ==========
    exePath := fmt.Sprintf("/proc/%d/exe", pid)
    exeLink, err := os.Readlink(exePath)
    if err == nil {
        proc.Executable = &FileInfo{Path: exeLink}
    }

    return proc, nil
}

// procfsWorker 后台从 procfs 查询进程
func (pt *ProcessTree) procfsWorker() {
    for {
        select {
        case <-pt.ctx.Done():
            return

        case pid := <-pt.procfsChan:
            // 从 procfs 读取进程
            proc, err := pt.readProcessFromProcfs(pid)
            if err != nil {
                continue
            }

            // 添加到缓存
            hash := pt.hashTaskID(proc.PID, proc.TID, 0)
            pt.processesLRU.Add(hash, proc)
        }
    }
}
```

---

## 4. 容器信息获取

### 4.1 容器检测原理

```
┌─────────────────────────────────────────────────────────────┐
│              Tracee 容器检测和信息获取流程                    │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  步骤1: Cgroup 检测                                          │
│  ┌────────────────────────────────────────────────────────┐│
│  │  读取 /proc/[pid]/cgroup                               ││
│  │  ↓                                                     ││
│  │  示例内容:                                              ││
│  │    0::/docker/abc123...                               ││
│  │    0::/kubepods/pod-uuid/container-id                 ││
│  │  ↓                                                     ││
│  │  提取容器 ID: abc123...                                ││
│  └────────────────────────────────────────────────────────┘│
│                           │                                 │
│                           ▼                                 │
│  步骤2: 运行时 API 查询                                      │
│  ┌────────────────────────────────────────────────────────┐│
│  │  并行查询多个运行时:                                     ││
│  │  ┌──────────────┐  ┌──────────────┐  ┌─────────────┐ ││
│  │  │  Docker      │  │  containerd  │  │  CRI-O      │ ││
│  │  │  /var/run/   │  │  /run/       │  │  /var/run/  │ ││
│  │  │  docker.sock │  │  containerd/ │  │  crio.sock  │ ││
│  │  └──────┬───────┘  └──────┬───────┘  └──────┬──────┘ ││
│  │         │                 │                 │         ││
│  │         └─────────────────┼─────────────────┘         ││
│  │                           │                           ││
│  │  返回容器信息:              ▼                           ││
│  │  • Name: nginx-web                                    ││
│  │  • Image: nginx:1.21                                  ││
│  │  • ImageDigest: sha256:abc123...                      ││
│  └────────────────────────────────────────────────────────┘│
│                           │                                 │
│                           ▼                                 │
│  步骤3: Kubernetes 元数据 (可选)                             │
│  ┌────────────────────────────────────────────────────────┐│
│  │  通过 CRI API 或 K8s API 获取:                          ││
│  │  • Pod Name                                            ││
│  │  • Pod Namespace                                       ││
│  │  • Pod UID                                             ││
│  │  • Labels                                              ││
│  └────────────────────────────────────────────────────────┘│
│                           │                                 │
│                           ▼                                 │
│  步骤4: 缓存                                                 │
│  ┌────────────────────────────────────────────────────────┐│
│  │  存储到 LRU Cache:                                      ││
│  │  ContainerID → Container {Name, Image, Pod, ...}      ││
│  └────────────────────────────────────────────────────────┘│
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### 4.2 核心实现 - [pkg/containers/containers.go](pkg/containers/containers.go)

#### 容器管理器结构

```go
// Manager 包含运行中容器的信息
type Manager struct {
    cgroups      *cgroup.Cgroups           // Cgroup 管理器
    cgroupsMap   map[uint32]CgroupDir      // Cgroup ID → 目录信息
    containerMap map[string]Container      // 容器 ID → 容器信息
    deleted      []uint64                  // 已删除容器的 ID
    lock         sync.RWMutex              // 保护并发访问
    enricher     runtime.Service           // 运行时适配器
    bpfMapName   string                    // BPF Map 名称
}

// Container 表示一个容器
type Container struct {
    ContainerId string            // 容器 ID
    CreatedAt   time.Time         // 创建时间
    Runtime     runtime.RuntimeId // 运行时类型
    Name        string            // 容器名称
    Image       string            // 镜像名称
    ImageDigest string            // 镜像摘要
    Pod         Pod               // Pod 信息 (K8s)
}

// Pod 表示 Kubernetes Pod
type Pod struct {
    Name      string // Pod 名称
    Namespace string // 命名空间
    UID       string // Pod UID
    Sandbox   bool   // 是否为 sandbox 容器
}
```

#### 创建容器管理器

```go
func New(
    noContainersEnrich bool,
    cgroups *cgroup.Cgroups,
    sockets runtime.Sockets,
    mapName string,
) (*Manager, error) {
    containers := &Manager{
        cgroups:      cgroups,
        cgroupsMap:   make(map[uint32]CgroupDir),
        containerMap: make(map[string]Container),
        lock:         sync.RWMutex{},
        bpfMapName:   mapName,
    }

    // ========== 初始化运行时适配器 ==========
    if !noContainersEnrich {
        enricher, err := runtime.NewRuntimeService(sockets)
        if err != nil {
            return nil, errfmt.WrapError(err)
        }
        containers.enricher = enricher
    }

    return containers, nil
}
```

#### 获取容器信息

```go
// GetContainer 根据容器 ID 获取容器信息
func (m *Manager) GetContainer(containerID string) (*Container, error) {
    m.lock.RLock()

    // ========== 1. 检查缓存 ==========
    if container, ok := m.containerMap[containerID]; ok {
        m.lock.RUnlock()
        return &container, nil
    }

    m.lock.RUnlock()

    // ========== 2. 缓存未命中，从运行时查询 ==========
    if m.enricher == nil {
        return nil, errfmt.Errorf("container enricher not initialized")
    }

    // 调用运行时 API
    info, err := m.enricher.GetContainerInfo(containerID)
    if err != nil {
        return nil, errfmt.WrapError(err)
    }

    // ========== 3. 转换为 Container 结构 ==========
    container := Container{
        ContainerId: containerID,
        CreatedAt:   info.CreatedAt,
        Runtime:     info.Runtime,
        Name:        info.Name,
        Image:       info.Image,
        ImageDigest: info.ImageDigest,
    }

    // 如果是 Kubernetes，获取 Pod 信息
    if info.Pod != nil {
        container.Pod = Pod{
            Name:      info.Pod.Name,
            Namespace: info.Pod.Namespace,
            UID:       info.Pod.UID,
            Sandbox:   info.Pod.Sandbox,
        }
    }

    // ========== 4. 缓存结果 ==========
    m.lock.Lock()
    m.containerMap[containerID] = container
    m.lock.Unlock()

    return &container, nil
}
```

#### 运行时适配器 - [pkg/containers/runtime/service.go](pkg/containers/runtime/service.go)

```go
// Service 定义运行时服务接口
type Service interface {
    GetContainerInfo(containerID string) (*ContainerInfo, error)
    GetPodInfo(containerID string) (*PodInfo, error)
}

// RuntimeService 实现多运行时支持
type RuntimeService struct {
    docker     *DockerClient
    containerd *ContainerdClient
    crio       *CRIOClient
}

// NewRuntimeService 创建运行时服务
func NewRuntimeService(sockets Sockets) (Service, error) {
    svc := &RuntimeService{}

    // ========== 初始化 Docker 客户端 ==========
    if sockets.Docker != "" {
        client, err := NewDockerClient(sockets.Docker)
        if err == nil {
            svc.docker = client
        }
    }

    // ========== 初始化 containerd 客户端 ==========
    if sockets.Containerd != "" {
        client, err := NewContainerdClient(sockets.Containerd)
        if err == nil {
            svc.containerd = client
        }
    }

    // ========== 初始化 CRI-O 客户端 ==========
    if sockets.CRIO != "" {
        client, err := NewCRIOClient(sockets.CRIO)
        if err == nil {
            svc.crio = client
        }
    }

    return svc, nil
}

// GetContainerInfo 从任何可用运行时获取容器信息
func (s *RuntimeService) GetContainerInfo(containerID string) (*ContainerInfo, error) {
    // ========== 尝试 Docker ==========
    if s.docker != nil {
        info, err := s.docker.GetContainerInfo(containerID)
        if err == nil {
            return info, nil
        }
    }

    // ========== 尝试 containerd ==========
    if s.containerd != nil {
        info, err := s.containerd.GetContainerInfo(containerID)
        if err == nil {
            return info, nil
        }
    }

    // ========== 尝试 CRI-O ==========
    if s.crio != nil {
        info, err := s.crio.GetContainerInfo(containerID)
        if err == nil {
            return info, nil
        }
    }

    return nil, errfmt.Errorf("container not found in any runtime")
}
```

---

## 5. DNS 缓存机制

### 5.1 DNS 缓存设计

```
┌──────────────────────────────────────────────────────────────┐
│                    DNSCache 树形结构                          │
├──────────────────────────────────────────────────────────────┤
│                                                               │
│  LRU Cache (根节点)                                           │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  queryRoots: domain → dnsNode                        │   │
│  │                                                       │   │
│  │  "google.com" ──▶ dnsNode {                          │   │
│  │                     Query: "google.com"              │   │
│  │                     TTL: 300                         │   │
│  │                     Expires: 2025-01-10 12:05:00     │   │
│  │                     Answers: [                       │   │
│  │                       {Type: A, Data: "142.250.185.46"}│  │
│  │                     ]                                │   │
│  │                     Children: {                      │   │
│  │                       "www.google.com" → dnsNode {...}│  │
│  │                       "mail.google.com" → dnsNode {...}│ │
│  │                     }                                │   │
│  │                   }                                  │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                               │
│  索引映射 (快速查找)                                           │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  queryIndices: full_domain → dnsNode                 │   │
│  │  "www.google.com" ──▶ dnsNode {子域名}               │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                               │
└──────────────────────────────────────────────────────────────┘
```

### 5.2 核心实现 - [pkg/dnscache/dnscache.go](pkg/dnscache/dnscache.go)

#### DNS 缓存结构

```go
// DNSCache 缓存 DNS 查询和响应
type DNSCache struct {
    queryRoots   *lru.Cache[string, *dnsNode] // 根域名 → 节点
    queryIndices map[string]*dnsNode          // 完整域名 → 节点
    lock         *sync.RWMutex                // 并发保护
}

// dnsNode 表示 DNS 树中的一个节点
type dnsNode struct {
    Query    string                 // 查询的域名
    TTL      uint32                 // 生存时间 (秒)
    Expires  time.Time              // 过期时间
    Answers  []trace.ProtoDNSAnswer // DNS 响应记录
    Children map[string]*dnsNode    // 子域名
}

// ProtoDNSAnswer DNS 响应记录
type ProtoDNSAnswer struct {
    Type  string // A, AAAA, CNAME, MX, etc.
    TTL   uint32
    Answer string // IP 地址或域名
}
```

#### 添加 DNS 记录

```go
// Add 添加 DNS 事件到缓存
func (nc *DNSCache) Add(event *trace.Event) error {
    // ========== 1. 解析 DNS 参数 ==========
    dns, err := parse.ArgVal[trace.ProtoDNS](event.Args, "proto_dns")
    if err != nil {
        return err
    }

    // ========== 2. 检查是否为 DNS 响应 ==========
    if dns.QR != 1 || len(dns.Answers) < 1 {
        return nil // 不是响应或没有答案
    }

    if len(dns.Questions) != 1 {
        return errors.New("wrong number of requests found")
    }

    // ========== 3. 加锁处理 ==========
    nc.lock.Lock()
    defer nc.lock.Unlock()

    question := dns.Questions[0].Name
    questionNode, ok := nc.queryIndices[question]
    eventUnixTimestamp := time.Unix(0, int64(event.Timestamp))

    // ========== 4. 检查是否已索引 ==========
    if !ok {
        // 不存在，添加为根节点
        nc.addRootNode(&dns, eventUnixTimestamp)
    } else {
        // 存在，添加为子节点
        nc.addChildNodes(dns.Answers, questionNode, eventUnixTimestamp)
    }

    return nil
}

// addRootNode 添加根节点
func (nc *DNSCache) addRootNode(dns *trace.ProtoDNS, timestamp time.Time) {
    question := dns.Questions[0].Name

    // ========== 创建根节点 ==========
    rootNode := &dnsNode{
        Query:    question,
        Answers:  dns.Answers,
        Children: make(map[string]*dnsNode),
        Expires:  timestamp.Add(time.Duration(dns.Answers[0].TTL) * time.Second),
        TTL:      dns.Answers[0].TTL,
    }

    // ========== 添加到缓存 ==========
    nc.queryRoots.Add(question, rootNode)
    nc.queryIndices[question] = rootNode

    // ========== 处理 CNAME ==========
    for _, answer := range dns.Answers {
        if answer.Type == "CNAME" {
            // CNAME 指向的域名也添加到索引
            nc.queryIndices[answer.Answer] = rootNode
        }
    }
}

// addChildNodes 添加子节点
func (nc *DNSCache) addChildNodes(
    answers []trace.ProtoDNSAnswer,
    parentNode *dnsNode,
    timestamp time.Time,
) {
    for _, answer := range answers {
        childNode := &dnsNode{
            Query:    answer.Answer,
            Answers:  []trace.ProtoDNSAnswer{answer},
            Children: make(map[string]*dnsNode),
            Expires:  timestamp.Add(time.Duration(answer.TTL) * time.Second),
            TTL:      answer.TTL,
        }

        // 添加为子节点
        parentNode.Children[answer.Answer] = childNode

        // 索引子域名
        nc.queryIndices[answer.Answer] = childNode
    }
}
```

#### 查询 DNS 记录

```go
// Get 根据 IP 地址查询域名
func (nc *DNSCache) Get(ip string) ([]string, error) {
    nc.lock.RLock()
    defer nc.lock.RUnlock()

    var domains []string
    now := time.Now()

    // ========== 遍历所有节点查找 IP ==========
    for domain, node := range nc.queryIndices {
        // 检查是否过期
        if now.After(node.Expires) {
            continue
        }

        // 检查答案中是否包含该 IP
        for _, answer := range node.Answers {
            if answer.Type == "A" || answer.Type == "AAAA" {
                if answer.Answer == ip {
                    domains = append(domains, domain)
                }
            }
        }
    }

    if len(domains) == 0 {
        return nil, ErrDNSRecordNotFound
    }

    return domains, nil
}

// GetByDomain 根据域名查询 DNS 记录
func (nc *DNSCache) GetByDomain(domain string) (*dnsNode, error) {
    nc.lock.RLock()
    defer nc.lock.RUnlock()

    node, ok := nc.queryIndices[domain]
    if !ok {
        return nil, ErrDNSRecordNotFound
    }

    // 检查是否过期
    if time.Now().After(node.Expires) {
        return nil, ErrDNSRecordExpired
    }

    return node, nil
}
```

---

## 6. 符号表管理

### 6.1 符号表设计

```
┌──────────────────────────────────────────────────────────────┐
│                KernelSymbolTable (内核符号表)                 │
├──────────────────────────────────────────────────────────────┤
│                                                               │
│  符号映射 (地址 → 符号名)                                      │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  0xffffffffc0000000 ──▶ "nf_conntrack_init"         │   │
│  │  0xffffffffc0001234 ──▶ "tcp_v4_connect"            │   │
│  │  0xffffffffc0002468 ──▶ "sys_execve"                │   │
│  │  ...                                                 │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                               │
│  反向映射 (符号名 → 地址)                                      │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  "tcp_v4_connect" ──▶ 0xffffffffc0001234            │   │
│  │  "sys_execve" ──▶ 0xffffffffc0002468                │   │
│  │  ...                                                 │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                               │
│  符号所有者 (模块/内核)                                        │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  "nf_conntrack_init" ──▶ Owner: "nf_conntrack"      │   │
│  │  "tcp_v4_connect" ──▶ Owner: "kernel"               │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                               │
└──────────────────────────────────────────────────────────────┘
```

### 6.2 核心实现 - [pkg/symbols/symbols.go](pkg/symbols/symbols.go)

```go
// KernelSymbolTable 内核符号表
type KernelSymbolTable struct {
    symbols       map[uint64]string   // 地址 → 符号名
    addresses     map[string]uint64   // 符号名 → 地址
    symbolOwners  map[string]string   // 符号名 → 所有者 (模块)
    lock          sync.RWMutex
}

// NewKernelSymbolTable 创建内核符号表
func NewKernelSymbolTable() (*KernelSymbolTable, error) {
    table := &KernelSymbolTable{
        symbols:      make(map[uint64]string),
        addresses:    make(map[string]uint64),
        symbolOwners: make(map[string]string),
    }

    // ========== 从 /proc/kallsyms 加载符号 ==========
    if err := table.loadFromKallsyms(); err != nil {
        return nil, err
    }

    return table, nil
}

// loadFromKallsyms 从 /proc/kallsyms 加载符号
func (t *KernelSymbolTable) loadFromKallsyms() error {
    file, err := os.Open("/proc/kallsyms")
    if err != nil {
        return errfmt.WrapError(err)
    }
    defer file.Close()

    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        line := scanner.Text()

        // 解析格式: <地址> <类型> <符号名> [<模块>]
        // 示例: ffffffffc0000000 t nf_conntrack_init [nf_conntrack]
        fields := strings.Fields(line)
        if len(fields) < 3 {
            continue
        }

        // 解析地址
        addr, err := strconv.ParseUint(fields[0], 16, 64)
        if err != nil {
            continue
        }

        symbolName := fields[2]
        symbolType := fields[1]

        // 只保留函数符号 (t, T)
        if symbolType != "t" && symbolType != "T" {
            continue
        }

        // 存储映射
        t.symbols[addr] = symbolName
        t.addresses[symbolName] = addr

        // 解析模块名 (如果有)
        if len(fields) >= 4 {
            // 移除方括号
            moduleName := strings.Trim(fields[3], "[]")
            t.symbolOwners[symbolName] = moduleName
        } else {
            t.symbolOwners[symbolName] = "kernel"
        }
    }

    return scanner.Err()
}

// GetSymbolByAddr 根据地址获取符号名
func (t *KernelSymbolTable) GetSymbolByAddr(addr uint64) (string, error) {
    t.lock.RLock()
    defer t.lock.RUnlock()

    // ========== 精确匹配 ==========
    if symbol, ok := t.symbols[addr]; ok {
        return symbol, nil
    }

    // ========== 模糊匹配 (找最近的符号) ==========
    var closestSymbol string
    var closestAddr uint64

    for symAddr, symName := range t.symbols {
        if symAddr <= addr && symAddr > closestAddr {
            closestAddr = symAddr
            closestSymbol = symName
        }
    }

    if closestSymbol != "" {
        // 返回 "symbol+offset" 格式
        offset := addr - closestAddr
        return fmt.Sprintf("%s+0x%x", closestSymbol, offset), nil
    }

    return "", errfmt.Errorf("symbol not found for address 0x%x", addr)
}

// GetAddrBySymbol 根据符号名获取地址
func (t *KernelSymbolTable) GetAddrBySymbol(symbol string) (uint64, error) {
    t.lock.RLock()
    defer t.lock.RUnlock()

    if addr, ok := t.addresses[symbol]; ok {
        return addr, nil
    }

    return 0, errfmt.Errorf("address not found for symbol %s", symbol)
}

// GetSymbolOwner 获取符号所属的模块
func (t *KernelSymbolTable) GetSymbolOwner(symbol string) string {
    t.lock.RLock()
    defer t.lock.RUnlock()

    if owner, ok := t.symbolOwners[symbol]; ok {
        return owner
    }

    return "unknown"
}
```

---

## 7. 实践练习

### 练习 1：解码性能测试

**目标**：测量事件解码的性能

```go
// 在 pkg/bufferdecoder/decoder_test.go 添加基准测试
func BenchmarkDecodeEvent(b *testing.B) {
    // 准备测试数据
    rawEvent := generateTestEvent()
    typeDecoder := NewTypeDecoder()

    b.ResetTimer()

    for i := 0; i < b.N; i++ {
        decoder := New(rawEvent, typeDecoder)
        var event trace.Event
        err := decoder.DecodeContext(&event)
        if err != nil {
            b.Fatal(err)
        }
    }
}

// 运行基准测试
// go test -bench=BenchmarkDecodeEvent -benchmem ./pkg/bufferdecoder
```

### 练习 2：进程树可视化

**目标**：编写工具可视化进程树

```go
// 创建 tools/proctree-visualizer.go
package main

import (
    "fmt"
    "github.com/aquasecurity/tracee/pkg/proctree"
)

func printProcessTree(pt *proctree.ProcessTree, hash uint32, indent int) {
    proc, err := pt.GetProcess(hash)
    if err != nil {
        return
    }

    // 打印当前进程
    fmt.Printf("%s├─ PID: %d, CMD: %v\n",
        strings.Repeat("  ", indent),
        proc.PID,
        proc.Argv)

    // 递归打印子进程
    children := pt.GetChildren(hash)
    for _, childHash := range children {
        printProcessTree(pt, childHash, indent+1)
    }
}

func main() {
    // 初始化进程树
    ctx := context.Background()
    config := proctree.ProcTreeConfig{
        Source:               proctree.SourceEvents,
        ProcessCacheSize:     1000,
        ThreadCacheSize:      2000,
        ProcfsInitialization: true,
    }

    pt, err := proctree.NewProcessTree(ctx, config)
    if err != nil {
        panic(err)
    }

    // 打印进程树 (从 PID 1 开始)
    printProcessTree(pt, pt.HashTaskID(1, 1, 0), 0)
}
```

### 练习 3：DNS 缓存统计

**目标**：实现 DNS 缓存统计功能

```go
// 在 pkg/dnscache/dnscache.go 添加
func (nc *DNSCache) GetStatistics() map[string]interface{} {
    nc.lock.RLock()
    defer nc.lock.RUnlock()

    stats := make(map[string]interface{})

    // 统计总记录数
    stats["total_records"] = len(nc.queryIndices)

    // 统计根节点数
    stats["root_nodes"] = nc.queryRoots.Len()

    // 统计过期记录
    now := time.Now()
    expiredCount := 0
    for _, node := range nc.queryIndices {
        if now.After(node.Expires) {
            expiredCount++
        }
    }
    stats["expired_records"] = expiredCount

    // 统计记录类型分布
    typeDistribution := make(map[string]int)
    for _, node := range nc.queryIndices {
        for _, answer := range node.Answers {
            typeDistribution[answer.Type]++
        }
    }
    stats["type_distribution"] = typeDistribution

    return stats
}

// 使用示例
stats := dnsCache.GetStatistics()
fmt.Printf("DNS Cache Stats: %+v\n", stats)
```

### 练习 4：容器事件丰富

**目标**：观察容器元数据丰富过程

```go
// 在 pkg/ebpf/events_enrich.go 添加详细日志
func (t *Tracee) enrichContainerEvents(...) {
    // ... 原有代码

    for event := range in {
        if event.Container.ID != "" {
            logger.Debugw("Enriching container event",
                "event_id", event.EventID,
                "container_id", event.Container.ID,
            )

            container, err := t.containers.GetContainer(event.Container.ID)
            if err != nil {
                logger.Warnw("Failed to get container info",
                    "container_id", event.Container.ID,
                    "error", err,
                )
            } else {
                logger.Debugw("Container info retrieved",
                    "name", container.Name,
                    "image", container.Image,
                    "pod", container.Pod.Name,
                )

                // 丰富事件
                event.Container.Name = container.Name
                event.Container.Image = container.Image
                event.Kubernetes.PodName = container.Pod.Name
                event.Kubernetes.PodNamespace = container.Pod.Namespace
            }
        }

        out <- event
    }
}

// 运行并查看日志
// sudo ./dist/tracee -l debug -e security_file_open --scope container=new
```

---

## 8. 总结与下一步

### 本阶段掌握的内容

- ✅ 事件解码器的二进制协议解析
- ✅ 进程树的树形数据结构设计
- ✅ 容器信息获取和运行时适配
- ✅ DNS 缓存的树形结构实现
- ✅ 内核符号表的加载和查询

### 关键技术点

| 技术 | 应用场景 | 优势 |
|------|---------|------|
| **LRU Cache** | 进程树、DNS缓存、容器信息 | 自动驱逐、内存可控 |
| **sync.Pool** | 事件对象、Feed对象 | 减少GC压力 |
| **RWMutex** | 并发读写保护 | 读多写少场景性能好 |
| **Procfs** | 进程信息补充 | 兼容性好、信息全面 |

### 性能优化总结

1. **对象池**：减少频繁分配
2. **LRU 缓存**：限制内存使用
3. **零拷贝**：直接操作原始缓冲区
4. **读写锁**：优化并发访问
5. **批量操作**：减少系统调用

### 下一步学习

继续第五阶段：**[策略与检测引擎](05-policy-engine.md)**

重点内容：
- 策略 YAML 解析和验证
- 策略管理器实现
- Scope 和 Event 过滤详解
- 签名引擎架构
- 自定义签名开发

---

**上一篇**：[第三阶段：eBPF 实现](03-ebpf-implementation.md) | **下一篇**：[第五阶段：策略引擎](05-policy-engine.md)
