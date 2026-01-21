# Tracee 进程树与缓存机制深度解析

| 学习时长 | 难度等级 | 前置知识 |
|---------|---------|---------|
| 2-3 天 | ⭐⭐⭐ | Go 语言、Linux 进程模型、eBPF 基础 |

## 目录

1. [概述与学习目标](#概述与学习目标)
2. [进程树架构](#进程树架构)
   - [ProcessTree 数据结构](#processtree-数据结构)
   - [进程信息获取 (/proc)](#进程信息获取-proc)
   - [进程关系维护](#进程关系维护)
   - [Fork/Exec 事件处理](#forkexec-事件处理)
3. [容器信息缓存](#容器信息缓存)
   - [缓存结构设计](#缓存结构设计)
   - [信息来源](#信息来源)
   - [更新与失效策略](#更新与失效策略)
4. [DNS 缓存](#dns-缓存)
   - [缓存实现](#dns-缓存实现)
   - [查询与更新](#查询与更新)
5. [缓存设计模式](#缓存设计模式)
   - [LRU 策略](#lru-策略)
   - [并发安全](#并发安全)
   - [内存管理](#内存管理)
6. [与 eBPF 的数据交互](#与-ebpf-的数据交互)
7. [动手练习](#动手练习)
8. [核心代码走读](#核心代码走读)

---

## 概述与学习目标

### 为什么需要进程树和缓存？

在安全监控场景中，Tracee 需要：

1. **追溯进程血缘关系**：当检测到可疑行为时，需要知道是哪个进程链触发的
2. **关联容器上下文**：将事件与容器、Pod 关联起来
3. **解析网络连接**：将 IP 地址解析为域名，便于分析
4. **高效查询**：在事件处理的热路径上快速获取上下文信息

### 学习目标

完成本教程后，你将能够：

- [ ] 理解 Tracee 进程树的数据结构和组织方式
- [ ] 掌握进程信息从 eBPF 和 procfs 两个来源的获取方式
- [ ] 理解容器信息缓存的设计和更新机制
- [ ] 理解 DNS 缓存的图结构设计
- [ ] 掌握 LRU 缓存、对象池、Changelog 等缓存设计模式
- [ ] 能够为 Tracee 扩展新的缓存机制

### 核心源码文件

```
pkg/proctree/           # 进程树实现
├── proctree.go         # 主结构体和创建逻辑
├── process.go          # Process 结构体
├── thread.go           # Thread 结构体
├── taskinfo.go         # 任务信息
├── fileinfo.go         # 文件信息
├── taskid.go           # 任务 ID 哈希
├── proctree_feed.go    # Fork/Exec/Exit 事件处理
├── proctree_procfs.go  # procfs 信息获取
├── datasource.go       # DataSource 接口实现
└── proctree_output.go  # 调试输出

pkg/containers/         # 容器信息管理
├── containers.go       # 容器缓存主逻辑
├── datasource.go       # DataSource 接口实现
└── runtime/            # 容器运行时

pkg/dnscache/           # DNS 缓存
├── dnscache.go         # 缓存主逻辑
├── node.go             # 图节点
├── query.go            # 查询逻辑
└── datasource.go       # DataSource 接口实现

common/changelog/       # 时间序列变更日志
├── changelog.go        # Changelog 结构
└── entry.go            # Entry 结构
```

---

## 进程树架构

### ProcessTree 数据结构

Tracee 的进程树采用 **双层结构**：Process（进程）和 Thread（线程），通过 hash 关联。

```
┌─────────────────────────────────────────────────────────────────────┐
│                         ProcessTree                                  │
├─────────────────────────────────────────────────────────────────────┤
│  processesLRU: LRU Cache [hash -> *Process]                        │
│  threadsLRU: LRU Cache [hash -> *Thread]                           │
│  processesThreads: map[processHash] -> set{threadHashes}           │
│  processesChildren: map[processHash] -> set{childHashes}           │
│  procfsChan: channel for async procfs reads                        │
│  object pools: ForkFeed, ExecFeed, ExitFeed, TaskInfoFeed...       │
└─────────────────────────────────────────────────────────────────────┘
         │                          │
         ▼                          ▼
┌─────────────────┐        ┌─────────────────┐
│     Process     │        │     Thread      │
├─────────────────┤        ├─────────────────┤
│ processHash     │        │ threadHash      │
│ parentHash      │        │ parentHash      │
│ info: *TaskInfo │◄──────►│ leaderHash      │
│ executable:     │        │ info: *TaskInfo │
│   *FileInfo     │        └─────────────────┘
└─────────────────┘
```

**核心设计原则**：

1. **Thread Group Leader = Process**：线程组领导者在进程树中被视为"进程"
2. **共享 TaskInfo**：同一 hash 的 Process 和 Thread 共享相同的 TaskInfo 指针
3. **LRU 缓存**：使用 LRU 缓存控制内存使用
4. **原子操作**：使用 `atomic.Uint32` 确保并发安全

#### ProcessTree 主结构

```go
// 文件: pkg/proctree/proctree.go

type ProcessTree struct {
    processesLRU      *lru.Cache[uint32, *Process]   // hash -> process
    threadsLRU        *lru.Cache[uint32, *Thread]    // hash -> threads
    processesThreads  map[uint32]map[uint32]struct{} // process hash -> thread hashes
    processesChildren map[uint32]map[uint32]struct{} // process hash -> children hashes
    procfsChan        chan int32                     // 异步 procfs 读取 channel
    procfsOnce        *sync.Once                     // 节流日志
    ctx               context.Context
    procfsQuery       bool                           // 是否启用 procfs 查询

    // 互斥锁
    processesThreadsMtx  sync.RWMutex
    processesChildrenMtx sync.RWMutex

    // 对象池 - 减少 GC 压力
    forkFeedPool     *sync.Pool
    execFeedPool     *sync.Pool
    exitFeedPool     *sync.Pool
    taskInfoFeedPool *sync.Pool
    fileInfoFeedPool *sync.Pool
}

const (
    DefaultProcessCacheSize = 10928  // 默认进程缓存大小
    DefaultThreadCacheSize  = 21856  // 默认线程缓存大小 (约为进程的2倍)
)
```

#### Process 和 Thread 结构

```go
// 文件: pkg/proctree/process.go

type Process struct {
    processHash uint32        // 进程 hash (不可变)
    parentHash  atomic.Uint32 // 父进程 hash (可变，进程可能被重新父化)
    info        *TaskInfo     // 任务信息 (指针不可变)
    executable  *FileInfo     // 可执行文件信息 (指针不可变)
}

// 文件: pkg/proctree/thread.go

type Thread struct {
    threadHash uint32        // 线程 hash (不可变)
    parentHash atomic.Uint32 // 父进程 hash
    leaderHash atomic.Uint32 // 线程组领导者 hash
    _          [4]byte       // 内存对齐填充
    info       *TaskInfo     // 任务信息 (共享)
}
```

#### 任务 ID 哈希

进程/线程的唯一标识通过 **PID + 启动时间** 的 MurmurHash3 计算：

```go
// 文件: pkg/proctree/taskid.go

// HashTaskID 创建任务 ID 的一致性哈希
// 时间戳按 USER_HZ 精度取整，确保与 procfs 读取兼容
func HashTaskID(pid uint32, startTime uint64) uint32 {
    // USER_HZ 通常为 100HZ (10ms)
    // 取整到 100ms 精度以兼容 procfs
    round := startTime / 100000000 // (1000000000 / USER_HZ) * 10 = 100000000
    round *= 100000000
    return murmur.HashU32AndU64(pid, round)
}
```

**为什么需要时间戳？**

- PID 会被复用（Linux 的 PID 范围有限）
- 同一个 PID 在不同时间可能代表不同的进程
- 加上启动时间可以唯一标识一个进程

### 进程信息获取 (/proc)

Tracee 从两个来源获取进程信息：

1. **eBPF 事件**：实时、精确，但需要进程活动才能触发
2. **procfs**：启动时扫描，补充缺失信息

```
                    ┌──────────────────┐
                    │   ProcessTree    │
                    └────────┬─────────┘
                             │
           ┌─────────────────┴─────────────────┐
           │                                   │
           ▼                                   ▼
┌─────────────────────┐             ┌─────────────────────┐
│   eBPF 事件 (实时)   │             │  procfs (初始化/补充) │
├─────────────────────┤             ├─────────────────────┤
│ - Fork 事件         │             │ - /proc/<pid>/stat  │
│ - Exec 事件         │             │ - /proc/<pid>/status│
│ - Exit 事件         │             │ - /proc/<pid>/task/ │
│ - 信号事件          │             └─────────────────────┘
└─────────────────────┘
```

#### procfs 异步读取

```go
// 文件: pkg/proctree/proctree_procfs.go

// FeedFromProcFSAsync 异步从 procfs 获取进程信息
func (pt *ProcessTree) FeedFromProcFSAsync(givenPid int32) {
    if pt.procfsChan == nil {
        logger.Debugw("starting procfs proctree loop")
        pt.procfsChan = make(chan int32, 1000)  // 带缓冲的 channel
        pt.feedFromProcFSLoop()
    }

    // 非阻塞发送，如果 channel 满了就跳过
    select {
    case pt.procfsChan <- givenPid:
    default:
        pt.procfsOnce.Do(func() {
            logger.Debugw("procfs proctree loop is busy")
        })
    }
}

// feedFromProcFSLoop 后台处理循环
func (pt *ProcessTree) feedFromProcFSLoop() {
    go func() {
        for {
            select {
            case <-time.After(15 * time.Second):
                pt.procfsOnce = new(sync.Once) // 重置日志节流
            case <-pt.ctx.Done():
                return
            case givenPid := <-pt.procfsChan:
                _ = pt.FeedFromProcFS(givenPid)
            }
        }
    }()
}
```

#### 从 procfs 解析进程信息

```go
// 文件: pkg/proctree/proctree_procfs.go

func dealWithProc(pt *ProcessTree, givenPid int32) error {
    // 读取 /proc/<pid>/stat 获取启动时间
    stat, err := proc.NewProcStatFields(givenPid, []proc.StatField{
        proc.StatStartTime,
    })
    if err != nil {
        return errfmt.WrapError(err)
    }

    // 读取 /proc/<pid>/status 获取进程信息
    status, err := proc.NewProcStatus(givenPid)
    if err != nil {
        return errfmt.WrapError(err)
    }

    // 提取关键信息
    name := status.GetName()
    pid := status.GetPid()
    tgid := status.GetTgid()
    ppid := status.GetPPid()
    nspid := status.GetNsPid()
    start := stat.GetStartTime()

    // 计算进程 hash
    startTimeNs := timeutil.ClockTicksToNsSinceBootTime(start)
    epochTimeNs := timeutil.BootToEpochNS(startTimeNs)
    processHash := HashTaskID(uint32(pid), epochTimeNs)

    // 更新进程树
    process := pt.GetOrCreateProcessByHash(processHash)
    procInfo := process.GetInfo()

    // 使用对象池获取 feed 结构
    taskInfoFeed := pt.GetTaskInfoFeedFromPool()
    defer pt.PutTaskInfoFeedInPool(taskInfoFeed)

    taskInfoFeed.Name = name
    taskInfoFeed.Tid = pid
    taskInfoFeed.Pid = tgid
    taskInfoFeed.PPid = ppid
    taskInfoFeed.NsTid = nspid
    // ... 设置其他字段

    procInfo.SetFeedAt(taskInfoFeed, timeutil.NsSinceEpochToTime(epochTimeNs))

    return nil
}
```

### 进程关系维护

进程树维护两种关系：**父子关系** 和 **线程组关系**。

```
                     ┌─────────────┐
                     │   Parent    │
                     │ (Process)   │
                     └──────┬──────┘
                            │ children
              ┌─────────────┼─────────────┐
              ▼             ▼             ▼
        ┌─────────┐   ┌─────────┐   ┌─────────┐
        │ Child 1 │   │ Child 2 │   │ Child 3 │
        │(Leader) │   │(Process)│   │(Process)│
        └────┬────┘   └─────────┘   └─────────┘
             │ threads
     ┌───────┼───────┐
     ▼       ▼       ▼
┌────────┐┌────────┐┌────────┐
│Thread 1││Thread 2││Thread 3│
│(Leader)││        ││        │
└────────┘└────────┘└────────┘
```

#### 关系维护方法

```go
// 文件: pkg/proctree/proctree.go

// AddChildToProcess 添加子进程
func (pt *ProcessTree) AddChildToProcess(processHash uint32, childHash uint32) {
    if processHash == 0 || childHash == 0 {
        return
    }

    pt.processesChildrenMtx.Lock()
    defer pt.processesChildrenMtx.Unlock()

    if _, ok := pt.processesChildren[processHash]; !ok {
        pt.processesChildren[processHash] = make(map[uint32]struct{})
    }

    pt.processesChildren[processHash][childHash] = struct{}{}
}

// AddThreadToProcess 添加线程到进程
func (pt *ProcessTree) AddThreadToProcess(processHash uint32, threadHash uint32) {
    if processHash == 0 || threadHash == 0 {
        return
    }

    pt.processesThreadsMtx.Lock()
    defer pt.processesThreadsMtx.Unlock()

    if _, ok := pt.processesThreads[processHash]; !ok {
        pt.processesThreads[processHash] = make(map[uint32]struct{})
    }

    pt.processesThreads[processHash][threadHash] = struct{}{}
}

// GetChildren 获取子进程列表
func (pt *ProcessTree) GetChildren(processHash uint32) []uint32 {
    pt.processesChildrenMtx.RLock()
    defer pt.processesChildrenMtx.RUnlock()

    childrenMap, ok := pt.processesChildren[processHash]
    if !ok {
        return nil
    }

    children := make([]uint32, 0, len(childrenMap))
    for child := range childrenMap {
        children = append(children, child)
    }
    return children
}
```

### Fork/Exec 事件处理

Fork 和 Exec 是进程树更新的核心事件。

#### Fork 事件处理流程

```
Fork 事件到达
      │
      ▼
┌─────────────────────────────────────┐
│ 1. 解析事件参数                      │
│    - 父进程信息                      │
│    - 线程组领导者信息                 │
│    - 子进程/线程信息                  │
└───────────────┬─────────────────────┘
                │
                ▼
┌─────────────────────────────────────┐
│ 2. 计算各进程 Hash                   │
│    HashTaskID(pid, startTime)       │
└───────────────┬─────────────────────┘
                │
                ▼
┌─────────────────────────────────────┐
│ 3. 更新/创建父进程节点               │
│    - GetOrCreateProcessByHash       │
│    - 设置 TaskInfo                   │
└───────────────┬─────────────────────┘
                │
                ▼
┌─────────────────────────────────────┐
│ 4. 更新/创建 Leader 节点             │
│    - 设置父进程关系                   │
│    - 继承父进程可执行文件信息          │
└───────────────┬─────────────────────┘
                │
                ▼
┌─────────────────────────────────────┐
│ 5. 创建 Thread 节点                  │
│    - 设置 leaderHash                 │
│    - 添加到进程的线程列表             │
└─────────────────────────────────────┘
```

```go
// 文件: pkg/proctree/proctree_feed.go

func (pt *ProcessTree) FeedFromFork(feed *ForkFeed) error {
    if feed.ChildHash == 0 || feed.ParentHash == 0 {
        return errfmt.Errorf("invalid task hash")
    }

    feedTimeStamp := timeutil.NsSinceEpochToTime(feed.TimeStamp)

    // 1. 更新父进程
    parent, found := pt.GetProcessByHash(feed.ParentHash)
    if !found {
        parent = pt.GetOrCreateProcessByHash(feed.ParentHash)
    }

    if !found || parent.GetInfo().GetPid() != feed.ParentPid {
        pt.setParentFeed(parent, feed, feedTimeStamp)
    }

    // 添加 leader 作为父进程的子进程
    pt.AddChildToProcess(feed.ParentHash, feed.LeaderHash)

    // 2. 更新 Leader (线程组领导者)
    leader, found := pt.GetProcessByHash(feed.LeaderHash)
    if !found {
        leader = pt.GetOrCreateProcessByHash(feed.LeaderHash)
    }

    if !found || leader.GetInfo().GetPPid() != feed.ParentPid {
        pt.setLeaderFeed(leader, parent, feed, feedTimeStamp)
    }

    leader.SetParentHash(feed.ParentHash)

    // 3. 如果 child == leader，复制父进程的可执行文件信息
    if feed.ChildHash == feed.LeaderHash {
        fileInfoFeed := parent.GetExecutable().GetFeed()
        leader.GetExecutable().SetFeedAt(&fileInfoFeed, feedTimeStamp)
    }

    // 4. 创建/更新 Thread
    thread, found := pt.GetThreadByHash(feed.ChildHash)
    if !found {
        thread = pt.GetOrCreateThreadByHash(feed.ChildHash)
    }

    if !found || thread.GetInfo().GetPPid() != feed.ParentPid {
        pt.setThreadFeed(thread, leader, feed, feedTimeStamp)
    }

    thread.SetParentHash(feed.ParentHash)
    thread.SetLeaderHash(feed.LeaderHash)
    pt.AddThreadToProcess(feed.LeaderHash, feed.ChildHash)

    return nil
}
```

#### Exec 事件处理

```go
// 文件: pkg/proctree/proctree_feed.go

func (pt *ProcessTree) FeedFromExec(feed *ExecFeed) error {
    // 线程执行 execve() 的情况（不常见但可能发生）
    if feed.LeaderHash != 0 && feed.TaskHash != feed.LeaderHash {
        logger.Debugw("exec event received for a thread", "taskHash", feed.TaskHash)
        return nil
    }

    // 获取或创建进程节点
    process := pt.GetOrCreateProcessByHash(feed.TaskHash)

    if feed.ParentHash != 0 {
        process.SetParentHash(feed.ParentHash)
    }

    execTimestamp := timeutil.NsSinceEpochToTime(feed.TimeStamp)
    basename := filepath.Base(feed.CmdPath)
    comm := string([]byte(basename[:min(len(basename), COMM_LEN)]))

    // 更新任务信息
    taskFeed := pt.GetTaskInfoFeedFromPool()
    defer pt.PutTaskInfoFeedInPool(taskFeed)

    taskFeed.StartTimeNS = feed.StartTime
    taskFeed.Name = comm
    taskFeed.NsTid = feed.Tid
    taskFeed.NsPid = feed.Pid
    // ... 其他字段

    process.GetInfo().SetFeedAt(taskFeed, execTimestamp)

    // 更新可执行文件信息
    fileInfoFeed := pt.GetFileInfoFeedFromPool()
    defer pt.PutFileInfoFeedInPool(fileInfoFeed)

    fileInfoFeed.Path = feed.PathName
    fileInfoFeed.Dev = feed.Dev
    fileInfoFeed.Ctime = feed.Ctime
    fileInfoFeed.Inode = feed.Inode
    fileInfoFeed.InodeMode = feed.InodeMode

    process.GetExecutable().SetFeedAt(fileInfoFeed, execTimestamp)

    return nil
}
```

---

## 容器信息缓存

### 缓存结构设计

容器信息缓存维护 **cgroup ID** 到 **容器信息** 的映射。

```
┌────────────────────────────────────────────────────────────────┐
│                        Manager                                  │
├────────────────────────────────────────────────────────────────┤
│  cgroupsMap: map[uint32]CgroupDir    // cgroup ID -> 目录信息   │
│  containerMap: map[string]Container  // container ID -> 容器   │
│  deleted: []uint64                   // 待删除的 cgroup ID     │
│  enricher: runtime.Service           // 容器运行时服务         │
│  lock: sync.RWMutex                  // 并发保护              │
└────────────────────────────────────────────────────────────────┘
```

```go
// 文件: pkg/containers/containers.go

type Container struct {
    ContainerId string
    CreatedAt   time.Time
    Runtime     runtime.RuntimeId  // Docker, Containerd, Crio, Podman, Garden
    Name        string
    Image       string
    ImageDigest string
    Pod         Pod                // Kubernetes Pod 信息
}

type Pod struct {
    Name      string
    Namespace string
    UID       string
    Sandbox   bool
}

type CgroupDir struct {
    Path          string
    ContainerId   string
    ContainerRoot bool      // 是否是容器的 cgroup 根目录
    Ctime         time.Time
    Dead          bool      // cgroup 是否已删除
    expiresAt     time.Time // 过期时间（延迟删除）
}
```

### 信息来源

容器信息从多个来源获取：

```
┌──────────────────┐     ┌──────────────────┐     ┌──────────────────┐
│    cgroup 事件   │     │   cgroupfs 扫描   │     │  容器运行时 API  │
│  (mkdir/rmdir)  │     │   (初始化时)      │     │  (enrichment)   │
└────────┬─────────┘     └────────┬─────────┘     └────────┬─────────┘
         │                        │                        │
         └────────────────────────┼────────────────────────┘
                                  │
                                  ▼
                    ┌─────────────────────────┐
                    │     Container Manager   │
                    └─────────────────────────┘
```

#### 从 cgroup 路径解析容器 ID

```go
// 文件: pkg/containers/containers.go

// parseContainerIdFromCgroupPath 从 cgroup 路径解析容器 ID
func parseContainerIdFromCgroupPath(cgroupPath string) (string, runtime.RuntimeId, bool) {
    cgroupParts := strings.Split(cgroupPath, "/")

    // 从后向前搜索，获取最内层的容器 ID
    for i := len(cgroupParts) - 1; i >= 0; i-- {
        pc := cgroupParts[i]
        if len(pc) < 28 {
            continue // 容器 ID 至少 28 字符
        }

        contRuntime := runtime.Unknown
        id := strings.TrimSuffix(pc, ".scope")

        switch {
        case strings.HasPrefix(id, "docker-"):
            contRuntime = runtime.Docker
            id = strings.TrimPrefix(id, "docker-")
        case strings.HasPrefix(id, "crio-"):
            contRuntime = runtime.Crio
            id = strings.TrimPrefix(id, "crio-")
        case strings.HasPrefix(id, "cri-containerd-"):
            contRuntime = runtime.Containerd
            id = strings.TrimPrefix(id, "cri-containerd-")
        case strings.HasPrefix(id, "libpod-"):
            contRuntime = runtime.Podman
            id = strings.TrimPrefix(id, "libpod-")
        }

        if contRuntime != runtime.Unknown {
            return id, contRuntime, i == len(cgroupParts)-1
        }

        // 检查是否匹配 64 位十六进制容器 ID
        if matched := containerIdFromCgroupRegex.MatchString(id); matched && i > 0 {
            prevPart := cgroupParts[i-1]
            if prevPart == "docker" {
                contRuntime = runtime.Docker
            }
            // ... 其他判断
        }
    }

    return "", runtime.Unknown, false
}
```

### 更新与失效策略

#### 延迟删除策略

```go
// 文件: pkg/containers/containers.go

// CgroupRemove 删除 cgroup 信息，带 30 秒延迟
func (c *Manager) CgroupRemove(cgroupId uint64, hierarchyID uint32) {
    const expiryTime = 30 * time.Second

    now := time.Now()
    var deleted []uint64

    c.lock.Lock()
    defer c.lock.Unlock()

    // 处理之前标记为删除的 cgroup
    for _, id := range c.deleted {
        info := c.cgroupsMap[uint32(id)]
        if now.After(info.expiresAt) {
            // 真正删除
            contId := c.cgroupsMap[uint32(id)].ContainerId
            delete(c.cgroupsMap, uint32(id))
            delete(c.containerMap, contId)
        } else {
            deleted = append(deleted, id)
        }
    }
    c.deleted = deleted

    // 标记当前 cgroup 为待删除
    if info, ok := c.cgroupsMap[uint32(cgroupId)]; ok {
        info.expiresAt = now.Add(expiryTime)
        info.Dead = true
        c.cgroupsMap[uint32(cgroupId)] = info
        c.deleted = append(c.deleted, cgroupId)
    }
}
```

**为什么需要延迟删除？**

- 避免竞态条件：cgroup 删除事件可能在容器退出事件之前到达
- 事件可能乱序：需要保留一段时间以关联后续事件
- 30 秒的窗口通常足够处理所有相关事件

#### 容器信息丰富（Enrichment）

```go
// 文件: pkg/containers/containers.go

func (c *Manager) EnrichCgroupInfo(cgroupId uint64) (Container, error) {
    c.lock.Lock()
    defer c.lock.Unlock()

    info, ok := c.cgroupsMap[uint32(cgroupId)]
    if !ok {
        return Container{}, errfmt.Errorf("cgroup %d not found", cgroupId)
    }

    containerId := info.ContainerId
    if containerId == "" {
        return Container{}, nil // 不是容器
    }

    container := c.containerMap[containerId]

    // 如果已经有镜像信息，说明已丰富过
    if container.Image != "" {
        return container, nil
    }

    // 调用容器运行时 API 获取详细信息
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()

    enrichRes, err := c.enricher.Get(ctx, containerId, container.Runtime)
    if err != nil {
        return Container{}, errfmt.WrapError(err)
    }

    // 更新容器信息
    container = Container{
        ContainerId: containerId,
        Name:        enrichRes.ContName,
        Image:       enrichRes.Image,
        ImageDigest: enrichRes.ImageDigest,
        Pod: Pod{
            Name:      enrichRes.PodName,
            Namespace: enrichRes.Namespace,
            UID:       enrichRes.UID,
            Sandbox:   enrichRes.Sandbox,
        },
    }

    c.containerMap[containerId] = container
    return container, nil
}
```

---

## DNS 缓存

### DNS 缓存实现

DNS 缓存采用 **图结构**，支持域名和 IP 的双向查询。

```
                    ┌─────────────────┐
                    │  DNS Root Node  │
                    │ "example.com"   │
                    └────────┬────────┘
                             │
              ┌──────────────┼──────────────┐
              ▼              ▼              ▼
        ┌──────────┐   ┌──────────┐   ┌──────────┐
        │  CNAME   │   │    A     │   │   AAAA   │
        │"www.xxx" │   │"1.2.3.4" │   │"2001::1" │
        └────┬─────┘   └──────────┘   └──────────┘
             │
             ▼
       ┌──────────┐
       │    A     │
       │"5.6.7.8" │
       └──────────┘
```

```go
// 文件: pkg/dnscache/dnscache.go

type DNSCache struct {
    queryRoots   *lru.Cache[string, *dnsNode]  // 查询根节点 LRU 缓存
    queryIndices map[string]*dnsNode           // 所有节点的索引
    lock         *sync.RWMutex
}

const DefaultCacheSize = 5000  // 最大查询根节点数

// 文件: pkg/dnscache/node.go

type nodeType int

const (
    InvalidNode nodeType = iota
    DNS                           // 域名节点
    IP                            // IP 地址节点
)

type dnsNode struct {
    value        string                        // 节点值（域名或 IP）
    nodeType     nodeType
    expiredAfter time.Time                     // TTL 过期时间
    parents      *set.Set[*dnsNode, string]    // 父节点集合
    next         *set.Set[*dnsNode, string]    // 子节点集合
}
```

### 查询与更新

#### 添加 DNS 响应

```go
// 文件: pkg/dnscache/dnscache.go

func (nc *DNSCache) Add(event *trace.Event) error {
    dns, err := parse.ArgVal[trace.ProtoDNS](event.Args, "proto_dns")
    if err != nil {
        return err
    }

    // 只处理 DNS 响应
    if dns.QR != 1 || len(dns.Answers) < 1 {
        return nil
    }

    nc.lock.Lock()
    defer nc.lock.Unlock()

    question := dns.Questions[0].Name
    questionNode, ok := nc.queryIndices[question]
    eventUnixTimestamp := time.Unix(0, int64(event.Timestamp))

    if !ok {
        // 创建新的根节点
        nc.addRootNode(&dns, eventUnixTimestamp)
    } else {
        // 添加子节点到现有节点
        nc.addChildNodes(dns.Answers, questionNode, eventUnixTimestamp)
    }
    return nil
}
```

#### 查询 DNS 记录

```go
// 文件: pkg/dnscache/dnscache.go

func (nc *DNSCache) Get(key string) (cacheQuery, error) {
    nc.lock.RLock()
    defer nc.lock.RUnlock()

    // 清理反向查询后缀
    key = strings.TrimSuffix(key, ".in-addr.arpa")
    key = strings.TrimSuffix(key, ".ip6.arpa")

    node, ok := nc.queryIndices[key]
    if !ok {
        return cacheQuery{}, ErrDNSRecordNotFound
    }

    queryResult := cacheQuery{
        dnsResults: []string{},
        ipResults:  []string{},
    }

    queryTime := time.Now()

    // 检查是否过期
    if queryTime.After(node.expiredAfter) {
        return cacheQuery{}, ErrDNSRecordExpired
    }

    // 遍历图获取相关节点
    nc.addSingleNodeToQueryResult(node, &queryResult, false)
    nc.addNodeChildrenToQueryResult(node, &queryResult, queryTime)
    nc.addNodeParentsToQueryResult(node, &queryResult, queryTime)

    return queryResult, nil
}
```

#### TTL 处理

```go
// 文件: pkg/dnscache/node.go

func (n *dnsNode) updateTTL(ttl uint32, timestamp time.Time) {
    n.expiredAfter = timestamp.Add(time.Second * time.Duration(ttl))
}

// makeNodeFromAnswer 从 DNS 响应创建节点
func makeNodeFromAnswer(parent *dnsNode, answer *trace.ProtoDNSResourceRecord, timestamp time.Time) *dnsNode {
    nodeType := DNS
    value := ""

    switch answer.Type {
    case "CNAME":
        value = answer.CNAME
    case "A", "AAAA":
        value = answer.IP
        nodeType = IP
    case "MX":
        value = answer.MX.Name
    case "SRV":
        value = answer.SRV.Name
    case "PTR":
        value = answer.PTR
    }

    return &dnsNode{
        value:        value,
        nodeType:     nodeType,
        expiredAfter: timestamp.Add(time.Duration(answer.TTL) * time.Second),
        parents:      newNodeSet(parent),
        next:         newNodeSet(),
    }
}
```

---

## 缓存设计模式

### LRU 策略

Tracee 使用 HashiCorp 的 golang-lru 库实现 LRU 缓存。

```go
// 文件: pkg/proctree/proctree.go

func NewProcessTree(ctx context.Context, config ProcTreeConfig) (*ProcessTree, error) {
    procTree := &ProcessTree{...}

    var procEvicted, thrEvicted int

    // 创建带驱逐回调的 LRU 缓存
    procTree.processesLRU, err = lru.NewWithEvict[uint32, *Process](
        config.ProcessCacheSize,
        func(key uint32, value *Process) {
            // 驱逐时清理相关的线程和子进程映射
            procTree.EvictThreads(key)
            procTree.EvictChildren(key)
            procEvicted++
        },
    )

    procTree.threadsLRU, err = lru.NewWithEvict[uint32, *Thread](
        config.ThreadCacheSize,
        func(key uint32, value *Thread) {
            thrEvicted++
        },
    )

    // 定期报告缓存统计
    go func() {
        ticker15s := time.NewTicker(15 * time.Second)
        ticker1m := time.NewTicker(1 * time.Minute)

        for {
            select {
            case <-ctx.Done():
                return
            case <-ticker15s.C:
                if procEvicted != 0 || thrEvicted != 0 {
                    logger.Debugw("proctree cache stats",
                        "processes evicted", procEvicted,
                        "total processes", procTree.processesLRU.Len(),
                        "threads evicted", thrEvicted,
                        "total threads", procTree.threadsLRU.Len(),
                    )
                    procEvicted, thrEvicted = 0, 0
                }
            }
        }
    }()

    return procTree, nil
}
```

### 并发安全

Tracee 使用多种机制确保并发安全：

#### 1. 原子操作

```go
// 文件: pkg/proctree/process.go

type Process struct {
    processHash uint32            // 不可变，无需保护
    parentHash  atomic.Uint32     // 原子操作
    info        *TaskInfo         // 指针不可变
    executable  *FileInfo         // 指针不可变
}

func (p *Process) SetParentHash(parentHash uint32) {
    p.parentHash.Store(parentHash)
}

func (p *Process) GetParentHash() uint32 {
    return p.parentHash.Load()
}
```

#### 2. 读写锁

```go
// 文件: pkg/proctree/taskinfo.go

type TaskInfo struct {
    feed  *changelog.Changelog[*TaskInfoFeed]
    mutex *sync.RWMutex
}

func (ti *TaskInfo) GetFeed() TaskInfoFeed {
    ti.mutex.RLock()
    defer ti.mutex.RUnlock()
    return *ti.getFeed()  // 返回副本
}

func (ti *TaskInfo) SetFeed(feed *TaskInfoFeed) {
    ti.mutex.Lock()
    defer ti.mutex.Unlock()
    ti.setFeed(feed)
}
```

#### 3. 线程安全的 Set

```go
// 文件: common/set/set.go

type Set[T, H comparable] struct {
    *SimpleSet[T, H]
    l *sync.RWMutex
}

func (s *Set[T, H]) Has(item T) bool {
    s.l.RLock()
    defer s.l.RUnlock()
    return s.SimpleSet.Has(item)
}

func (s *Set[T, H]) Append(items ...T) {
    s.l.Lock()
    defer s.l.Unlock()
    s.SimpleSet.Append(items...)
}
```

### 内存管理

#### 对象池

```go
// 文件: pkg/proctree/proctree.go

// 使用 sync.Pool 复用对象，减少 GC 压力
procTree := &ProcessTree{
    forkFeedPool: &sync.Pool{
        New: func() interface{} {
            return &ForkFeed{}
        },
    },
    execFeedPool: &sync.Pool{
        New: func() interface{} {
            return &ExecFeed{}
        },
    },
    // ...
}

// 获取对象
func (pt *ProcessTree) GetForkFeedFromPool() *ForkFeed {
    return pt.forkFeedPool.Get().(*ForkFeed)
}

// 归还对象
func (pt *ProcessTree) PutForkFeedInPool(forkFeed *ForkFeed) {
    pt.forkFeedPool.Put(forkFeed)
}
```

**使用模式**：

```go
func (pt *ProcessTree) FeedFromFork(feed *ForkFeed) error {
    // 从池中获取对象
    taskInfoFeed := pt.GetTaskInfoFeedFromPool()
    defer pt.PutTaskInfoFeedInPool(taskInfoFeed)  // 确保归还

    // 使用对象
    taskInfoFeed.Name = "..."
    taskInfoFeed.Tid = feed.ParentTid
    // ...
}
```

#### Changelog 时间序列

```go
// 文件: common/changelog/changelog.go

// Changelog 管理单一类型的变更历史
type Changelog[T comparable] struct {
    list entryList[T]
}

// 创建时指定最大条目数
func NewChangelog[T comparable](maxEntries MaxEntries) *Changelog[T] {
    return &Changelog[T]{
        list: newEntryList[T](maxEntries),
    }
}

// Set 按时间戳顺序添加条目
func (c *Changelog[T]) Set(value T, timestamp time.Time) {
    c.list = c.list.set(value, timestamp)
}

// Get 获取指定时间点的值
func (c *Changelog[T]) Get(timestamp time.Time) T {
    return c.list.get(timestamp)
}

// GetCurrent 获取最新值
func (c *Changelog[T]) GetCurrent() T {
    return c.list.getCurrent()
}
```

**应用场景**：

```go
// TaskInfo 使用 Changelog 存储历史信息
type TaskInfo struct {
    feed  *changelog.Changelog[*TaskInfoFeed]  // 最多保存 3 个历史版本
    mutex *sync.RWMutex
}

func NewTaskInfo() *TaskInfo {
    return &TaskInfo{
        feed:  changelog.NewChangelog[*TaskInfoFeed](3),
        mutex: &sync.RWMutex{},
    }
}
```

---

## 与 eBPF 的数据交互

进程树与 eBPF 的数据交互有两条路径：

```
                    ┌─────────────────────────────────────────┐
                    │              eBPF Programs              │
                    │  (fork/exec/exit hooks, signals)        │
                    └───────────────────┬─────────────────────┘
                                        │
           ┌────────────────────────────┴─────────────────────────┐
           │                                                      │
           ▼                                                      ▼
┌─────────────────────────────┐              ┌─────────────────────────────┐
│     Control Plane           │              │     Event Pipeline          │
│  (Signal/快速路径)           │              │  (Event/事件处理管道)        │
├─────────────────────────────┤              ├─────────────────────────────┤
│ pkg/ebpf/controlplane/      │              │ pkg/ebpf/processor_*.go     │
│   processes.go              │              │   procTreeForkProcessor     │
│   procTreeForkProcessor     │              │   procTreeExecProcessor     │
│   procTreeExecProcessor     │              │   procTreeExitProcessor     │
└──────────────┬──────────────┘              └──────────────┬──────────────┘
               │                                            │
               └───────────────────┬────────────────────────┘
                                   │
                                   ▼
                    ┌─────────────────────────────────┐
                    │         ProcessTree             │
                    │    FeedFromFork/Exec/Exit       │
                    └─────────────────────────────────┘
```

### Control Plane 处理器

```go
// 文件: pkg/ebpf/controlplane/processes.go

func (ctrl *Controller) procTreeForkProcessor(args []trace.Argument) error {
    if ctrl.processTree == nil {
        return nil
    }

    forkFeed := ctrl.processTree.GetForkFeedFromPool()
    defer ctrl.processTree.PutForkFeedInPool(forkFeed)

    // 从信号参数解析
    forkFeed.TimeStamp, _ = parse.ArgVal[uint64](args, "timestamp")
    forkFeed.ParentTid, _ = parse.ArgVal[int32](args, "parent_process_tid")
    forkFeed.ParentStartTime, _ = parse.ArgVal[uint64](args, "parent_process_start_time")
    // ...

    // 计算 Hash
    forkFeed.ParentHash = proctree.HashTaskID(
        uint32(forkFeed.ParentTid),
        forkFeed.ParentStartTime,
    )
    forkFeed.LeaderHash = proctree.HashTaskID(
        uint32(forkFeed.LeaderTid),
        forkFeed.LeaderStartTime,
    )
    forkFeed.ChildHash = proctree.HashTaskID(
        uint32(forkFeed.ChildTid),
        forkFeed.ChildStartTime,
    )

    return ctrl.processTree.FeedFromFork(forkFeed)
}
```

### Event Pipeline 处理器

```go
// 文件: pkg/ebpf/processor_proctree.go

func (t *Tracee) procTreeForkProcessor(event *trace.Event) error {
    if t.processTree == nil {
        return errors.New("process tree is disabled")
    }

    forkFeed := t.processTree.GetForkFeedFromPool()
    defer t.processTree.PutForkFeedInPool(forkFeed)

    // 从事件参数解析
    forkFeed.ParentTid, _ = parse.ArgVal[int32](event.Args, "parent_process_tid")
    parentStartTime, _ := parse.ArgVal[time.Time](event.Args, "parent_process_start_time")
    forkFeed.ParentStartTime = uint64(parentStartTime.UnixNano())
    // ...

    forkFeed.TimeStamp = uint64(event.Timestamp)

    // 计算 Hash
    forkFeed.ParentHash = proctree.HashTaskID(
        uint32(forkFeed.ParentTid),
        forkFeed.ParentStartTime,
    )
    // ...

    return t.processTree.FeedFromFork(forkFeed)
}
```

### DataSource 接口

进程树、容器缓存、DNS 缓存都实现了统一的 DataSource 接口，供签名规则使用：

```go
// 文件: pkg/proctree/datasource.go

type DataSource struct {
    procTree *ProcessTree
}

func (ptds *DataSource) Keys() []string {
    return []string{"datasource.ProcKey", "datasource.ThreadKey", "datasource.LineageKey"}
}

func (ptds *DataSource) Get(key interface{}) (map[string]interface{}, error) {
    switch typedKey := key.(type) {
    case datasource.ProcKey:
        process, found := ptds.procTree.GetProcessByHash(typedKey.EntityId)
        if !found {
            return nil, detect.ErrDataNotFound
        }
        return map[string]interface{}{
            "process_info": ptds.exportProcessInfo(process, typedKey.Time),
        }, nil

    case datasource.ThreadKey:
        thread, found := ptds.procTree.GetThreadByHash(typedKey.EntityId)
        if !found {
            return nil, detect.ErrDataNotFound
        }
        return map[string]interface{}{
            "thread_info": ptds.exportThreadInfo(thread, typedKey.Time),
        }, nil

    case datasource.LineageKey:
        process, found := ptds.procTree.GetProcessByHash(typedKey.EntityId)
        if !found {
            return nil, detect.ErrDataNotFound
        }
        return map[string]interface{}{
            "process_lineage": ptds.exportProcessLineage(
                process, typedKey.Time, typedKey.MaxDepth,
            ),
        }, nil
    }

    return nil, detect.ErrKeyNotSupported
}
```

---

## 动手练习

### 练习 1：进程树查询工具

**目标**：实现一个简单的进程树查询工具，打印指定进程的父进程链。

**提示**：
- 使用 `GetProcessByHash` 和 `GetParentHash` 遍历
- 参考 `exportProcessLineage` 的实现

```go
// 文件: exercises/proctree_query.go

package main

import (
    "fmt"
    "github.com/aquasecurity/tracee/pkg/proctree"
)

func PrintProcessLineage(pt *proctree.ProcessTree, processHash uint32, maxDepth int) {
    process, found := pt.GetProcessByHash(processHash)
    if !found {
        fmt.Println("Process not found")
        return
    }

    current := process
    depth := 0

    for current != nil && depth < maxDepth {
        info := current.GetInfo()
        feed := info.GetFeed()

        fmt.Printf("%s[%d] %s (hash: %d)\n",
            strings.Repeat("  ", depth),
            feed.Pid,
            feed.Name,
            current.GetHash(),
        )

        // TODO: 获取父进程
        // 提示: 使用 current.GetParentHash() 和 pt.GetProcessByHash()
        parentHash := current.GetParentHash()
        if parentHash == 0 {
            break
        }
        current, found = pt.GetProcessByHash(parentHash)
        if !found {
            break
        }
        depth++
    }
}
```

### 练习 2：自定义缓存监控

**目标**：实现一个缓存监控器，定期输出缓存命中率统计。

```go
// 文件: exercises/cache_monitor.go

package main

type CacheMonitor struct {
    hits     uint64
    misses   uint64
    evictions uint64
    mu       sync.Mutex
}

func (m *CacheMonitor) RecordHit() {
    atomic.AddUint64(&m.hits, 1)
}

func (m *CacheMonitor) RecordMiss() {
    atomic.AddUint64(&m.misses, 1)
}

func (m *CacheMonitor) RecordEviction() {
    atomic.AddUint64(&m.evictions, 1)
}

func (m *CacheMonitor) GetHitRate() float64 {
    hits := atomic.LoadUint64(&m.hits)
    misses := atomic.LoadUint64(&m.misses)
    total := hits + misses
    if total == 0 {
        return 0
    }
    return float64(hits) / float64(total)
}

// TODO: 实现一个 goroutine 定期打印统计信息
```

### 练习 3：DNS 缓存扩展

**目标**：为 DNS 缓存添加反向查询支持（IP -> 域名）。

**提示**：
- 研究 `PTR` 记录的处理方式
- 参考 `addRootNode` 中对 PTR 记录的处理

### 练习 4：容器缓存持久化

**目标**：实现容器缓存的持久化，支持重启后恢复。

```go
// 文件: exercises/container_persistence.go

type ContainerPersistence struct {
    filepath string
    manager  *containers.Manager
}

// Save 保存容器信息到文件
func (p *ContainerPersistence) Save() error {
    // TODO: 序列化 containerMap 并写入文件
}

// Load 从文件恢复容器信息
func (p *ContainerPersistence) Load() error {
    // TODO: 从文件读取并反序列化到 containerMap
}
```

### 练习 5：进程血缘报告生成

**目标**：生成指定时间范围内所有进程的血缘报告。

要求：
1. 遍历进程树中所有进程
2. 构建父子关系图
3. 输出为可视化格式（DOT、JSON 或 Markdown）

---

## 核心代码走读

### 1. 进程树创建流程

```go
// 入口: pkg/proctree/proctree.go
func NewProcessTree(ctx context.Context, config ProcTreeConfig) (*ProcessTree, error) {
    // 1. 创建基本结构
    procTree := &ProcessTree{
        processesThreads:  make(map[uint32]map[uint32]struct{}),
        processesChildren: make(map[uint32]map[uint32]struct{}),
        // 创建对象池...
    }

    // 2. 创建 LRU 缓存（带驱逐回调）
    procTree.processesLRU, _ = lru.NewWithEvict[uint32, *Process](
        config.ProcessCacheSize,
        func(key uint32, value *Process) {
            procTree.EvictThreads(key)
            procTree.EvictChildren(key)
        },
    )

    // 3. 启动缓存统计 goroutine
    go func() { /* 统计逻辑 */ }()

    // 4. 如果启用，从 procfs 初始化
    if config.ProcfsInitialization {
        procTree.FeedFromProcFSAsync(AllPIDs)
    }

    return procTree, nil
}
```

### 2. Fork 事件处理流程

```go
// 入口: pkg/ebpf/processor_proctree.go
func (t *Tracee) procTreeForkProcessor(event *trace.Event) error {
    // 1. 从对象池获取 ForkFeed
    forkFeed := t.processTree.GetForkFeedFromPool()
    defer t.processTree.PutForkFeedInPool(forkFeed)

    // 2. 解析事件参数
    forkFeed.ParentTid, _ = parse.ArgVal[int32](event.Args, "parent_process_tid")
    // ...

    // 3. 计算 Hash
    forkFeed.ParentHash = proctree.HashTaskID(...)
    forkFeed.LeaderHash = proctree.HashTaskID(...)
    forkFeed.ChildHash = proctree.HashTaskID(...)

    // 4. 更新进程树
    return t.processTree.FeedFromFork(forkFeed)
}

// pkg/proctree/proctree_feed.go
func (pt *ProcessTree) FeedFromFork(feed *ForkFeed) error {
    // 1. 更新父进程
    parent := pt.GetOrCreateProcessByHash(feed.ParentHash)
    pt.setParentFeed(parent, feed, timestamp)
    pt.AddChildToProcess(feed.ParentHash, feed.LeaderHash)

    // 2. 更新 Leader
    leader := pt.GetOrCreateProcessByHash(feed.LeaderHash)
    pt.setLeaderFeed(leader, parent, feed, timestamp)
    leader.SetParentHash(feed.ParentHash)

    // 3. 复制可执行文件信息（如果是进程而非线程）
    if feed.ChildHash == feed.LeaderHash {
        fileInfoFeed := parent.GetExecutable().GetFeed()
        leader.GetExecutable().SetFeedAt(&fileInfoFeed, timestamp)
    }

    // 4. 创建 Thread
    thread := pt.GetOrCreateThreadByHash(feed.ChildHash)
    thread.SetParentHash(feed.ParentHash)
    thread.SetLeaderHash(feed.LeaderHash)
    pt.AddThreadToProcess(feed.LeaderHash, feed.ChildHash)

    return nil
}
```

### 3. 容器信息获取流程

```go
// 入口: pkg/containers/containers.go
func (c *Manager) GetCgroupInfo(cgroupId uint64) (CgroupDir, Container) {
    // 1. 检查缓存
    if !c.CgroupExists(cgroupId) {
        // 2. 从 cgroupfs 查找
        path, ctime, _ := cgroup.GetCgroupPath(
            c.cgroups.GetDefaultCgroup().GetMountPoint(),
            cgroupId,
            "",
        )
        // 3. 更新缓存
        c.cgroupUpdate(cgroupId, path, ctime, false)
    }

    // 4. 返回缓存数据
    cgroupInfo := c.cgroupsMap[uint32(cgroupId)]
    container := c.containerMap[cgroupInfo.ContainerId]
    return cgroupInfo, container
}

// 丰富容器信息
func (c *Manager) EnrichCgroupInfo(cgroupId uint64) (Container, error) {
    // 1. 检查是否已丰富
    container := c.containerMap[containerId]
    if container.Image != "" {
        return container, nil
    }

    // 2. 调用容器运行时 API
    enrichRes, _ := c.enricher.Get(ctx, containerId, container.Runtime)

    // 3. 更新缓存
    container = Container{
        ContainerId: containerId,
        Name:        enrichRes.ContName,
        Image:       enrichRes.Image,
        // ...
    }
    c.containerMap[containerId] = container

    return container, nil
}
```

### 4. DNS 缓存查询流程

```go
// 入口: pkg/dnscache/dnscache.go
func (nc *DNSCache) Get(key string) (cacheQuery, error) {
    nc.lock.RLock()
    defer nc.lock.RUnlock()

    // 1. 查找索引
    node, ok := nc.queryIndices[key]
    if !ok {
        return cacheQuery{}, ErrDNSRecordNotFound
    }

    // 2. 检查 TTL
    if time.Now().After(node.expiredAfter) {
        return cacheQuery{}, ErrDNSRecordExpired
    }

    // 3. 收集结果
    queryResult := cacheQuery{}

    // 添加当前节点
    nc.addSingleNodeToQueryResult(node, &queryResult, false)

    // 添加子节点（向下遍历）
    nc.addNodeChildrenToQueryResult(node, &queryResult, queryTime)

    // 添加父节点（向上遍历）
    nc.addNodeParentsToQueryResult(node, &queryResult, queryTime)

    return queryResult, nil
}
```

---

## 总结

### 关键设计决策

| 设计决策 | 原因 |
|---------|------|
| 双层结构 (Process + Thread) | 符合 Linux 进程模型，支持线程组概念 |
| PID + StartTime 哈希 | 解决 PID 复用问题，唯一标识进程 |
| LRU 缓存 | 控制内存使用，自动淘汰不活跃条目 |
| 对象池 | 减少 GC 压力，提高性能 |
| Changelog | 支持时间点查询，追溯历史状态 |
| 延迟删除 | 处理事件乱序，避免竞态条件 |
| DataSource 接口 | 统一访问方式，便于签名规则使用 |

### 性能考量

1. **热路径优化**：事件处理使用对象池
2. **并发控制**：读写锁分离，原子操作
3. **内存管理**：LRU 淘汰，限制路径长度
4. **异步处理**：procfs 读取不阻塞事件处理

### 扩展性

- 添加新的缓存类型：实现 DataSource 接口
- 添加新的数据来源：实现 Feed 方法
- 自定义驱逐策略：使用 LRU 的 evict callback

---

## 参考资料

1. [Tracee 官方文档](https://aquasecurity.github.io/tracee/)
2. [Linux 进程模型](https://man7.org/linux/man-pages/man7/namespaces.7.html)
3. [hashicorp/golang-lru](https://github.com/hashicorp/golang-lru)
4. [MurmurHash 算法](https://en.wikipedia.org/wiki/MurmurHash)

---

*本教程基于 Tracee 源码分析编写，版本信息以实际代码为准。*
