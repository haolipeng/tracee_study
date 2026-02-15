# 第六阶段：容器感知与集成

> **学习时长**：2-3 天 | **难度**：⭐⭐⭐ (中级)

## 学习目标

完成本阶段学习后，你将能够：

1. 理解 Tracee 如何检测和识别容器
2. 掌握 CGroup v1/v2 的解析机制
3. 了解多种容器运行时（Docker、containerd、CRI-O）的集成方式
4. 理解 Kubernetes 元数据的提取与丰富化过程
5. 掌握容器环境下的路径解析和事件关联
6. 理解 eBPF 中的容器识别机制

**预计学习时间：** 2-3 天

## 前置知识

在学习本阶段之前，请确保：
- 已完成第四阶段（Go 用户空间实现），理解 proctree 和 enrichment 机制
- 熟悉 Linux CGroup 基础概念
- 了解容器运行时的基本原理（Docker、containerd、Kubernetes）
- 理解第二阶段的事件丰富化流程

---

## 1. 容器检测架构概览

### 1.1 整体架构

Tracee 的容器感知系统包含三个核心层次：

```
┌─────────────────────────────────────────────────────────────────┐
│                       事件流 (Event Stream)                      │
└───────────────────────────────┬─────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                  CGroup 检测层 (CGroup Detection)                │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │ • 从事件上下文提取 cgroup_id                              │   │
│  │ • 解析 /proc/{pid}/cgroup 文件                           │   │
│  │ • 支持 CGroup v1 和 v2                                   │   │
│  │ • 通过 inode 匹配 cgroup 目录                            │   │
│  └──────────────────────────────────────────────────────────┘   │
└───────────────────────────────┬─────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│               容器 ID 提取层 (Container ID Extraction)           │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │ • 从 cgroup 路径提取容器 ID（64位十六进制）              │   │
│  │ • 识别容器运行时类型（Docker/containerd/CRI-O/Podman）  │   │
│  │ • 区分容器根目录和子目录                                 │   │
│  └──────────────────────────────────────────────────────────┘   │
└───────────────────────────────┬─────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│            运行时丰富化层 (Runtime Enrichment Service)           │
│  ┌────────────┬────────────┬────────────┬────────────────────┐  │
│  │  Docker    │ containerd │  CRI-O     │  Podman            │  │
│  │  Enricher  │  Enricher  │  Enricher  │  Enricher          │  │
│  └────────────┴────────────┴────────────┴────────────────────┘  │
│  查询运行时 API 获取：                                           │
│  • 容器名称                                                      │
│  • 镜像名称和摘要                                                │
│  • Kubernetes Pod 元数据（名称、命名空间、UID）                 │
│  • 是否为 Sandbox 容器                                          │
└─────────────────────────────────────────────────────────────────┘
```

### 1.2 数据结构

**核心容器信息结构** ([pkg/containers/containers.go:24](../../../pkg/containers/containers.go#L24)):

```go
// Container 包含容器的完整元数据
type Container struct {
    ContainerId string            // 容器 ID（64位十六进制字符串）
    CreatedAt   time.Time         // 创建时间（从 cgroup 目录 ctime 获取）
    Runtime     runtime.RuntimeId // 运行时类型（Docker/containerd/CRI-O/Podman）
    Name        string            // 容器名称（从运行时 API 获取）
    Image       string            // 镜像名称（如：nginx:latest）
    ImageDigest string            // 镜像摘要（SHA256）
    Pod         Pod               // Kubernetes Pod 信息
}

type Pod struct {
    Name      string  // Pod 名称
    Namespace string  // K8s 命名空间
    UID       string  // Pod UID
    Sandbox   bool    // 是否为 Pause/Sandbox 容器
}
```

**CGroup 目录信息** ([pkg/containers/containers.go:53](../../../pkg/containers/containers.go#L53)):

```go
// CgroupDir 表示一个 cgroup 目录（可能属于容器）
type CgroupDir struct {
    Path          string    // 相对于 cgroupfs 挂载点的路径
    ContainerId   string    // 提取的容器 ID（如果是容器目录）
    ContainerRoot bool      // 是否为容器的根 cgroup 目录
    Ctime         time.Time // 目录创建时间（从 stat.Ctim 获取）
    Dead          bool      // 目录是否已被删除
    expiresAt     time.Time // 过期时间（删除后30秒过期）
}
```

**容器管理器** ([pkg/containers/containers.go:42](../../../pkg/containers/containers.go#L42)):

```go
type Manager struct {
    cgroups      *cgroup.Cgroups            // CGroup v1/v2 管理器
    cgroupsMap   map[uint32]CgroupDir       // cgroup ID (lower 32 bits) -> CgroupDir
    containerMap map[string]Container       // container ID -> Container
    deleted      []uint64                   // 待删除的 cgroup ID 列表（延迟删除）
    lock         sync.RWMutex               // 保护 cgroupsMap 和 containerMap
    enricher     runtime.Service            // 多运行时查询服务
    bpfMapName   string                     // eBPF map 名称
}
```

### 1.3 工作流程

```
1. eBPF 捕获事件（包含 cgroup_id）
         │
         ▼
2. 检查 cgroupsMap[cgroup_id]
         │
         ├─ 存在 ──────────────────────────┐
         │                                  │
         ├─ 不存在 ─> 调用 GetCgroupPath() │
         │            搜索 cgroupfs        │
         │            解析路径提取 ID       │
         │            更新 cgroupsMap       │
         │                                  │
         └──────────────────────────────────┤
                                            ▼
3. 检查 containerMap[container_id]
         │
         ├─ 已丰富化 ──> 直接返回容器信息
         │
         └─ 未丰富化 ──> 调用 EnrichCgroupInfo()
                         │
                         ▼
4. Runtime Service 查询
   (Docker/containerd/CRI-O)
         │
         ▼
5. 解析响应，提取：
   - 容器名称
   - 镜像信息
   - K8s 标签（如果存在）
         │
         ▼
6. 更新 containerMap
   返回丰富化后的容器信息
```

---

## 2. CGroup 深度解析

### 2.1 CGroup 版本检测

Linux 支持 CGroup v1 和 v2 两个版本，Tracee 需要自动检测并支持两者。

**版本检测逻辑** ([common/cgroup/cgroup.go:329](../../../common/cgroup/cgroup.go#L329)):

```go
func GetCgroupDefaultVersion() (CgroupVersion, error) {
    // 方法1：检查 /sys/fs/cgroup/cgroup.controllers 文件
    // 如果存在，说明 cgroupv2 已挂载并作为默认版本
    if ok, _ := IsCgroupV2MountedAndDefault(); ok {
        return CgroupVersion2, nil
    }

    // 方法2：读取 /proc/cgroups 文件
    // 检查 cpuset 控制器的 hierarchy ID：
    // - ID = 0: 表示 (a) 未挂载到 v1 / (b) 绑定到 v2 / (c) 已禁用
    // - ID > 0: 表示挂载到 v1 hierarchy
    file, err := os.Open("/proc/cgroups")
    if err != nil {
        return -1, CouldNotOpenFile("/proc/cgroups", err)
    }
    defer file.Close()

    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        line := strings.Fields(scanner.Text())
        if line[0] != "cpuset" {
            continue
        }
        value, err := strconv.Atoi(line[1])  // hierarchy ID
        if err != nil || value < 0 {
            return -1, ErrorParsingFile("/proc/cgroups", err)
        }
        if value == 0 {
            return CgroupVersion2, nil
        }
        return CgroupVersion1, nil
    }

    return CgroupVersion2, nil
}
```

**关键概念：**
- **CGroup v1**：每个控制器（cpuset, memory, cpu等）单独挂载，可能有不同的 hierarchy
- **CGroup v2**：统一 hierarchy，所有控制器挂载到同一个目录
- **Hierarchy ID**：v1 中每个控制器有唯一的 hierarchy ID（>0），v2 中为 0

### 2.2 CGroup 挂载管理

**CGroup v1 初始化** ([common/cgroup/cgroup.go:215](../../../common/cgroup/cgroup.go#L215)):

```go
func (c *CgroupV1) init(cgroupfsPath string, forceMount bool) error {
    // 1. 检查内核是否支持 cgroupv1 文件系统
    supported, err := mount.IsFileSystemSupported("cgroup")
    if err != nil {
        return errfmt.WrapError(err)
    }
    if !supported {
        return &VersionNotSupported{}
    }

    // 2. 挂载 cgroup（如果需要）
    // 使用 cpuset 作为默认控制器
    c.mounted, err = mount.NewMountHostOnce(
        mount.Config{
            Source: "cgroup",
            FsType: "cgroup",
            Data:   "cpuset",  // 挂载选项：指定控制器
            Where:  cgroupfsPath,
            Force:  forceMount,
        },
    )
    if err != nil {
        return errfmt.WrapError(err)
    }

    // 3. 记录挂载点
    c.mountpoint = c.mounted.GetMountpoint()

    // 4. 验证挂载点 inode 是否为 1（主机 cgroup namespace）
    inode := c.mounted.GetMountpointInode()
    if inode != 1 {
        logger.Warnw("Cgroup mountpoint is not in the host cgroup namespace",
            "mountpoint", c.mountpoint, "inode", inode)
    }

    return nil
}
```

**CGroup v2 初始化** ([common/cgroup/cgroup.go:274](../../../common/cgroup/cgroup.go#L274)):

```go
func (c *CgroupV2) init(cgroupfsPath string, forceMount bool) error {
    // 1. 检查内核是否支持 cgroupv2
    supported, err := mount.IsFileSystemSupported("cgroup2")
    if err != nil {
        return errfmt.WrapError(err)
    }
    if !supported {
        return &VersionNotSupported{}
    }

    // 2. 挂载 cgroup v2
    // 注意：v2 没有 Data 选项（无需指定控制器）
    c.mounted, err = mount.NewMountHostOnce(
        mount.Config{
            Source: "cgroup2",
            FsType: "cgroup2",
            Data:   "",           // v2 没有控制器选项
            Where:  cgroupfsPath,
            Force:  forceMount,
        },
    )
    if err != nil {
        return errfmt.WrapError(err)
    }

    c.mountpoint = c.mounted.GetMountpoint()

    inode := c.mounted.GetMountpointInode()
    if inode != 1 {
        logger.Warnw("Cgroup mountpoint is not in the host cgroup namespace",
            "mountpoint", c.mountpoint, "inode", inode)
    }

    return nil
}
```

### 2.3 从进程获取 CGroup ID

**核心逻辑** ([common/cgroup/cgroup.go:488](../../../common/cgroup/cgroup.go#L488)):

```go
// GetCgroupID 返回给定进程和 cgroup 版本的 cgroup ID（inode 号）
func GetCgroupID(pid int32, cgroupVersion CgroupVersion) (uint64, error) {
    if pid <= 0 {
        return 0, errfmt.Errorf("invalid pid %d: must be positive", pid)
    }

    // 1. 读取 /proc/{pid}/cgroup 文件
    cgroupFile := "/proc/" + strconv.Itoa(int(pid)) + "/cgroup"
    cgroupData, err := os.ReadFile(cgroupFile)
    if err != nil {
        return 0, errfmt.Errorf("failed to read cgroup file %s: %v", cgroupFile, err)
    }

    // 2. 解析文件找到对应版本的 cgroup 路径
    // /proc/PID/cgroup 格式：
    // hierarchy-ID:controller-list:cgroup-path
    //
    // 例如：
    // CGroup v2: 0::/system.slice/docker-abc123.scope
    // CGroup v1: 3:cpuset:/docker/abc123
    cgroupPath := ""
    lines := strings.Split(string(cgroupData), "\n")
    for _, line := range lines {
        parts := strings.SplitN(line, ":", 3)
        if len(parts) < 3 {
            continue
        }

        // v2: hierarchy ID 为 0 且 controller-list 为空
        if cgroupVersion == CgroupVersion2 && (parts[1] == "" || parts[0] == "0") {
            cgroupPath = parts[2]
            break
        }

        // v1: 查找 cpuset 控制器
        if cgroupVersion == CgroupVersion1 && parts[1] == "cpuset" {
            cgroupPath = parts[2]
        }
    }

    if cgroupPath == "" {
        return 0, errfmt.Errorf("could not find cgroup path for pid %d", pid)
    }

    // 3. 构造完整的 cgroup 路径
    var fullCgroupPath string
    switch cgroupVersion {
    case CgroupVersion1:
        fullCgroupPath = filepath.Join("/sys/fs/cgroup/cpuset", cgroupPath)
    case CgroupVersion2:
        // 使用已有的挂载点检测功能
        cgroupV2Mountpoint, _, err := mount.SearchMountpointFromHost("cgroup2", "")
        if err != nil {
            return 0, errfmt.Errorf("failed to find cgroup v2 mount point: %v", err)
        }
        if cgroupV2Mountpoint == "" {
            return 0, errfmt.Errorf("could not find cgroup v2 mount point")
        }
        fullCgroupPath = filepath.Join(cgroupV2Mountpoint, cgroupPath)
    default:
        return 0, errfmt.Errorf("invalid cgroup version %d", cgroupVersion)
    }

    // 4. 获取 cgroup 目录的 inode 号（即 cgroup ID）
    // 关键事实：cgroupfs 中，目录的 inode 号 == cgroup ID
    var stat syscall.Stat_t
    if err := syscall.Stat(fullCgroupPath, &stat); err != nil {
        return 0, errfmt.Errorf("failed to stat cgroup path %s: %v", fullCgroupPath, err)
    }

    return stat.Ino, nil  // inode 号即为 cgroup ID
}
```

### 2.4 反向查找：从 CGroup ID 到路径

**迭代搜索算法** ([common/cgroup/cgroup.go:427](../../../common/cgroup/cgroup.go#L427)):

```go
// GetCgroupPath 迭代搜索 cgroupfs，找到匹配 cgroupId 的目录
//
// 关键原理：cgroupfs 中目录的 inode 号 == cgroup ID
// 我们检查 inode 号的低32位是否匹配 cgroup ID 的低32位
func GetCgroupPath(rootDir string, cgroupId uint64, subPath string) (string, time.Time, error) {
    // 使用栈实现深度优先搜索
    stack := []string{rootDir}

    for len(stack) > 0 {
        // 弹出栈顶目录
        currentDir := stack[len(stack)-1]
        stack = stack[:len(stack)-1]

        // 读取目录内容
        entries, err := os.ReadDir(currentDir)
        if err != nil {
            return "", time.Time{}, errfmt.WrapError(err)
        }

        for _, entry := range entries {
            // 只处理目录
            if !entry.IsDir() {
                continue
            }

            entryPath := filepath.Join(currentDir, entry.Name())

            // 如果提供了 subPath，检查路径是否匹配
            if strings.HasSuffix(entryPath, subPath) {
                // 获取 inode 信息
                var stat syscall.Stat_t
                if err := syscall.Stat(entryPath, &stat); err == nil {
                    // 检查低32位是否匹配
                    // 为什么只检查低32位？
                    // - eBPF maps 通常使用 u32 存储 cgroup ID
                    // - 低32位足以唯一标识 cgroup（碰撞概率极低）
                    if (stat.Ino & 0xFFFFFFFF) == (cgroupId & 0xFFFFFFFF) {
                        ctime := time.Unix(stat.Ctim.Sec, stat.Ctim.Nsec)
                        return entryPath, ctime, nil
                    }
                }
            }

            // 将目录压入栈以继续搜索
            stack = append(stack, entryPath)
        }
    }

    return "", time.Time{}, fs.ErrNotExist
}
```

**性能优化技巧：**
1. **提供 subPath**：如果知道容器 ID 或路径后缀，可以大大减少搜索范围
2. **缓存结果**：Manager 的 cgroupsMap 缓存所有已知的 cgroup ID -> 路径映射
3. **增量更新**：监听 `cgroup_mkdir` 和 `cgroup_rmdir` 事件，而不是定期全量扫描

---

## 3. 容器 ID 提取与运行时识别

### 3.1 CGroup 路径模式匹配

不同的容器运行时在 cgroupfs 中创建不同模式的路径：

```
Docker (systemd):
/sys/fs/cgroup/cpuset/system.slice/docker-<container-id>.scope

Docker (non-systemd):
/sys/fs/cgroup/cpuset/docker/<container-id>

containerd (systemd):
/sys/fs/cgroup/cpuset/system.slice/crio-<container-id>.scope

containerd (Kubernetes):
/sys/fs/cgroup/cpuset/kubepods/besteffort/pod<pod-id>/<container-id>
/sys/fs/cgroup/cpuset/kubepods/burstable/pod<pod-id>/<container-id>

CRI-O:
/sys/fs/cgroup/cpuset/crio-<container-id>.scope

Podman (systemd):
/sys/fs/cgroup/cpuset/libpod-<container-id>.scope

GitHub Actions (Docker):
/sys/fs/cgroup/cpuset/actions_job/<container-id>
```

### 3.2 解析算法实现

**核心解析函数** ([pkg/containers/containers.go:270](../../../pkg/containers/containers.go#L270)):

```go
// parseContainerIdFromCgroupPath 从 cgroup 路径提取容器 ID 和运行时类型
//
// 返回值：
// - containerId: 容器 ID（64位十六进制字符串）
// - runtimeId: 运行时类型
// - isRoot: 是否为容器的根 cgroup 目录
func parseContainerIdFromCgroupPath(cgroupPath string) (string, runtime.RuntimeId, bool) {
    cgroupParts := strings.Split(cgroupPath, "/")

    // 从路径末尾向前搜索，获取最内层的容器 ID
    // 这样可以正确处理嵌套容器的情况
    for i := len(cgroupParts) - 1; i >= 0; i = i - 1 {
        pc := cgroupParts[i]

        // 容器 ID 至少28个字符（缩短的容器 ID）
        if len(pc) < 28 {
            continue
        }

        contRuntime := runtime.Unknown
        id := strings.TrimSuffix(pc, ".scope")

        // 模式匹配1：systemd 格式（带前缀）
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

        case strings.Contains(pc, ":cri-containerd:"):
            // 另一种 containerd 格式
            contRuntime = runtime.Containerd
            id = pc[strings.LastIndex(pc, ":cri-containerd:")+len(":cri-containerd:"):]

        case strings.HasPrefix(id, "libpod-"):
            contRuntime = runtime.Podman
            id = strings.TrimPrefix(id, "libpod-")
        }

        if contRuntime != runtime.Unknown {
            // 找到匹配，返回结果
            // isRoot: 如果匹配在最后一个路径部分，则为容器根目录
            return id, contRuntime, i == len(cgroupParts)-1
        }

        // 模式匹配2：纯容器 ID（64位十六进制）
        if matched := containerIdFromCgroupRegex.MatchString(id); matched && i > 0 {
            prevPart := cgroupParts[i-1]

            if prevPart == "docker" {
                // 非 systemd 的 Docker: .../docker/01adbf...f26db7f/
                contRuntime = runtime.Docker
            }
            if prevPart == "actions_job" {
                // GitHub Actions 环境
                contRuntime = runtime.Docker
            }
            if strings.HasPrefix(prevPart, "pod") {
                // Kubernetes + containerd:
                // .../kubepods/<besteffort|burstable>/podXXX/01adbf...f26db7f/
                contRuntime = runtime.Containerd
            }

            return id, contRuntime, i == len(cgroupParts)-1
        }

        // 模式匹配3：Garden 容器（Cloud Foundry）
        // Garden 使用 UUID 格式的容器 ID
        if matched := gardenContainerIdFromCgroupRegex.MatchString(id); matched {
            contRuntime = runtime.Garden
            return id, contRuntime, i == len(cgroupParts)-1
        }
    }

    // 不是容器相关的 cgroup 目录
    return "", runtime.Unknown, false
}

// 正则表达式定义
var (
    // 标准容器 ID：64位十六进制
    containerIdFromCgroupRegex = regexp.MustCompile(`^[A-Fa-f0-9]{64}$`)

    // Garden 容器 ID：UUID 格式
    gardenContainerIdFromCgroupRegex = regexp.MustCompile(`^[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){4}$`)
)
```

### 3.3 CGroup 事件监听

Tracee 监听 cgroup 相关的内核事件来维护容器列表：

**CGroup 目录创建** ([pkg/containers/containers.go:384](../../../pkg/containers/containers.go#L384)):

```go
// CgroupMkdir 处理 cgroup 目录创建事件
func (c *Manager) CgroupMkdir(cgroupId uint64, subPath string, hierarchyID uint32) (CgroupDir, Container, error) {
    // CGroup v1: 只处理默认控制器的事件
    switch c.cgroups.GetDefaultCgroup().(type) {
    case *cgroup.CgroupV1:
        if c.cgroups.GetDefaultCgroupHierarchyID() != int(hierarchyID) {
            return CgroupDir{}, Container{}, nil
        }
    }

    c.lock.Lock()
    defer c.lock.Unlock()

    curTime := time.Now()

    // 在 cgroupfs 中查找新创建的目录
    path, ctime, err := cgroup.GetCgroupPath(
        c.cgroups.GetDefaultCgroup().GetMountPoint(),
        cgroupId,
        subPath,
    )

    if err == nil {
        // 找到了目录，使用真实的 ctime
        return c.cgroupUpdate(cgroupId, path, ctime, false)
    }

    // 未找到：容器可能已经退出
    // 仍然记录此 cgroup，但标记为 dead
    // ctime 使用当前时间作为估算值
    return c.cgroupUpdate(cgroupId, subPath, curTime, true)
}
```

**CGroup 目录删除** ([pkg/containers/containers.go:347](../../../pkg/containers/containers.go#L347)):

```go
// CgroupRemove 处理 cgroup 目录删除事件
// 使用延迟删除策略（30秒过期）避免竞态条件
func (c *Manager) CgroupRemove(cgroupId uint64, hierarchyID uint32) {
    const expiryTime = 30 * time.Second

    // CGroup v1: 只处理默认控制器
    switch c.cgroups.GetDefaultCgroup().(type) {
    case *cgroup.CgroupV1:
        if c.cgroups.GetDefaultCgroupHierarchyID() != int(hierarchyID) {
            return
        }
    }

    now := time.Now()
    var deleted []uint64

    c.lock.Lock()
    defer c.lock.Unlock()

    // 清理过期的 cgroup 信息
    for _, id := range c.deleted {
        info := c.cgroupsMap[uint32(id)]
        if now.After(info.expiresAt) {
            // 已过期，真正删除
            contId := c.cgroupsMap[uint32(id)].ContainerId
            delete(c.cgroupsMap, uint32(id))
            delete(c.containerMap, contId)
        } else {
            // 尚未过期，保留
            deleted = append(deleted, id)
        }
    }
    c.deleted = deleted

    // 标记新删除的 cgroup
    if info, ok := c.cgroupsMap[uint32(cgroupId)]; ok {
        info.expiresAt = now.Add(expiryTime)
        info.Dead = true
        c.cgroupsMap[uint32(cgroupId)] = info
        c.deleted = append(c.deleted, cgroupId)
    }
}
```

**为什么需要延迟删除？**
1. **事件顺序问题**：删除事件可能比使用此 cgroup 的其他事件先到达
2. **竞态条件**：多个 CPU 可能同时处理同一容器的事件
3. **优雅处理**：给正在处理的事件30秒的时间完成

---

## 4. 运行时适配器与 API 集成

### 4.1 运行时服务架构

**多运行时服务设计** ([pkg/containers/runtime/service.go:9](../../../pkg/containers/runtime/service.go#L9)):

```go
type Service struct {
    sockets   Sockets                        // 运行时 socket 路径配置
    enrichers map[RuntimeId]ContainerEnricher // 运行时 ID -> Enricher 映射
}

// NewService 初始化多运行时服务
func NewService(sockets Sockets) Service {
    return Service{
        enrichers: make(map[RuntimeId]ContainerEnricher),
        sockets:   sockets,
    }
}

// Register 注册一个运行时的 Enricher
func (e *Service) Register(
    rtime RuntimeId,
    enricherBuilder func(socket string) (ContainerEnricher, error),
) error {
    if !e.sockets.Supports(rtime) {
        return errfmt.Errorf("error registering enricher: unsupported runtime %s", rtime.String())
    }

    socket := e.sockets.Socket(rtime)
    enricher, err := enricherBuilder(socket)
    if err != nil {
        return errfmt.WrapError(err)
    }

    e.enrichers[rtime] = enricher
    return nil
}

// Get 查询容器元数据
func (e *Service) Get(ctx context.Context, containerId string, containerRuntime RuntimeId) (EnrichResult, error) {
    if containerRuntime == Unknown {
        // 运行时未知，尝试所有已注册的 enricher
        return e.getFromUnknownRuntime(ctx, containerId)
    }

    return e.getFromKnownRuntime(ctx, containerId, containerRuntime)
}

// getFromKnownRuntime 已知运行时的快速查询
func (e *Service) getFromKnownRuntime(ctx context.Context, containerId string, containerRuntime RuntimeId) (EnrichResult, error) {
    enricher := e.enrichers[containerRuntime]
    if enricher != nil {
        return enricher.Get(ctx, containerId)
    }
    return EnrichResult{}, errfmt.Errorf("unsupported runtime %s", containerRuntime.String())
}

// getFromUnknownRuntime 运行时未知时遍历所有 enricher
func (e *Service) getFromUnknownRuntime(ctx context.Context, containerId string) (EnrichResult, error) {
    for _, enricher := range e.enrichers {
        metadata, err := enricher.Get(ctx, containerId)
        if err == nil {
            return metadata, nil
        }
    }
    return EnrichResult{}, errfmt.Errorf("no runtime found for container")
}
```

### 4.2 Socket 自动发现

**默认路径探测** ([pkg/containers/runtime/sockets.go:42](../../../pkg/containers/runtime/sockets.go#L42)):

```go
// Autodiscover 自动发现系统中的容器运行时 socket
func Autodiscover(onRegisterFail func(err error, runtime RuntimeId, socket string)) Sockets {
    register := func(sockets *Sockets, runtime RuntimeId, socket string) {
        err := sockets.Register(runtime, socket)
        if err != nil {
            onRegisterFail(err, runtime, socket)
        }
    }

    sockets := Sockets{}

    // 各运行时的默认 socket 路径
    const (
        defaultContainerd = "/var/run/containerd/containerd.sock"
        defaultDocker     = "/var/run/docker.sock"
        defaultCrio       = "/var/run/crio/crio.sock"
        defaultPodman     = "/var/run/podman/podman.sock"
    )

    // 尝试注册所有支持的运行时
    register(&sockets, Containerd, defaultContainerd)
    register(&sockets, Docker, defaultDocker)
    register(&sockets, Crio, defaultCrio)
    register(&sockets, Podman, defaultPodman)

    return sockets
}

// Register 检查 socket 文件是否存在后注册
func (s *Sockets) Register(runtime RuntimeId, socket string) error {
    if s.sockets == nil {
        s.sockets = make(map[RuntimeId]string)
    }

    // 验证 socket 文件存在
    _, err := os.Stat(socket)
    if err != nil {
        return errfmt.Errorf("failed to register runtime socket %v", err)
    }

    s.sockets[runtime] = socket
    return nil
}
```

### 4.3 containerd Enricher

**containerd 查询实现** ([pkg/containers/runtime/containerd.go](../../../pkg/containers/runtime/containerd.go)):

```go
type containerdEnricher struct {
    client     *containerd.Client
    containers containerd.ContainerService
    criRuntime criapi.RuntimeServiceClient  // CRI 客户端
}

func (e *containerdEnricher) Get(ctx context.Context, containerId string) (EnrichResult, error) {
    var res EnrichResult

    // 1. 设置 containerd 命名空间
    // Kubernetes 使用 "k8s.io" 命名空间
    nsCtx := namespaces.WithNamespace(ctx, "k8s.io")

    // 2. 获取容器信息
    container, err := e.containers.Get(nsCtx, containerId)
    if err != nil {
        return res, errfmt.WrapError(err)
    }

    res.ContName = containerId  // 默认使用 ID
    labels := container.Labels

    // 3. 提取容器名称
    // Kubernetes 在标签中存储容器名称
    if name, ok := labels[ContainerNameLabel]; ok {
        res.ContName = name
    }

    // 4. 获取镜像信息
    // 优先尝试 containerd 镜像存储
    image := container.Image
    i, d, err := e.getImageInfoStore(nsCtx, image)
    if err != nil {
        // 失败则尝试 CRI API
        i, d, err2 := e.getImageInfoCri(nsCtx, image)
        if err2 != nil {
            return res, errfmt.Errorf("failed to get image info from both store and cri: %v, %v", err, err2)
        }
        res.Image = i
        res.ImageDigest = d
    } else {
        res.Image = i
        res.ImageDigest = d
    }

    // 5. 提取 Kubernetes 元数据（从标签）
    res.PodName = labels[PodNameLabel]           // io.kubernetes.pod.name
    res.Namespace = labels[PodNamespaceLabel]    // io.kubernetes.pod.namespace
    res.UID = labels[PodUIDLabel]                // io.kubernetes.pod.uid

    // 6. 检查是否为 Sandbox/Pause 容器
    if containerType, ok := labels[ContainerTypeLabel]; ok {
        res.Sandbox = (containerType == ContainerTypeSandbox)
    }

    return res, nil
}

// getImageInfoStore 从 containerd 镜像存储查询
func (e *containerdEnricher) getImageInfoStore(ctx context.Context, imageName string) (string, string, error) {
    img, err := e.client.GetImage(ctx, imageName)
    if err != nil {
        return "", "", errfmt.WrapError(err)
    }

    // 提取镜像名称和摘要
    imgName := img.Name()
    digest := img.Target().Digest.String()

    return imgName, digest, nil
}

// getImageInfoCri 从 CRI API 查询（备用方案）
func (e *containerdEnricher) getImageInfoCri(ctx context.Context, imageName string) (string, string, error) {
    // 查询镜像状态
    imageSpec := &criapi.ImageSpec{Image: imageName}
    resp, err := e.criRuntime.ImageStatus(ctx, &criapi.ImageStatusRequest{
        Image: imageSpec,
    })
    if err != nil {
        return "", "", errfmt.WrapError(err)
    }

    if resp.Image == nil {
        return "", "", errfmt.Errorf("image not found: %s", imageName)
    }

    // 提取 RepoTags（镜像名称）
    var imgName string
    if len(resp.Image.RepoTags) > 0 {
        imgName = resp.Image.RepoTags[0]
    }

    // 提取摘要
    digest := resp.Image.Id

    return imgName, digest, nil
}
```

**关键 Kubernetes 标签：**
```go
const (
    PodNameLabel        = "io.kubernetes.pod.name"
    PodNamespaceLabel   = "io.kubernetes.pod.namespace"
    PodUIDLabel         = "io.kubernetes.pod.uid"
    ContainerNameLabel  = "io.kubernetes.container.name"
    ContainerTypeLabel  = "io.kubernetes.container.type"
    ContainerTypeSandbox = "sandbox"  // Pause 容器
)
```

### 4.4 Docker Enricher

**Docker API 查询** ([pkg/containers/runtime/docker.go](../../../pkg/containers/runtime/docker.go)):

```go
type dockerEnricher struct {
    client *client.Client  // Docker HTTP API 客户端
}

func (e *dockerEnricher) Get(ctx context.Context, containerId string) (EnrichResult, error) {
    var res EnrichResult

    // 1. 调用 Docker API 获取容器详细信息
    resp, err := e.client.ContainerInspect(ctx, containerId)
    if err != nil {
        return res, errfmt.WrapError(err)
    }

    // 2. 提取容器名称（去掉前导斜杠）
    // Docker 容器名称格式：/container_name
    res.ContName = strings.TrimPrefix(resp.Name, "/")

    // 3. 提取镜像名称
    res.Image = resp.Config.Image

    // 4. 提取镜像摘要
    // 注意：需要单独查询镜像信息
    if resp.Image != "" {
        imageInspect, _, err := e.client.ImageInspectWithRaw(ctx, resp.Image)
        if err == nil && len(imageInspect.RepoDigests) > 0 {
            // RepoDigests 格式：[repo@sha256:digest, ...]
            res.ImageDigest = imageInspect.RepoDigests[0]
        }
    }

    // 5. 提取 Kubernetes 元数据（如果存在）
    // Kubernetes 使用 Docker 时会在标签中存储 Pod 信息
    if resp.Config.Labels != nil {
        labels := resp.Config.Labels
        res.PodName = labels[PodNameLabel]
        res.Namespace = labels[PodNamespaceLabel]
        res.UID = labels[PodUIDLabel]

        if containerType, ok := labels[ContainerTypeLabel]; ok {
            res.Sandbox = (containerType == ContainerTypeSandbox)
        }
    }

    return res, nil
}
```

### 4.5 丰富化流程

**完整的容器信息丰富化** ([pkg/containers/containers.go:196](../../../pkg/containers/containers.go#L196)):

```go
// EnrichCgroupInfo 丰富化容器信息
func (c *Manager) EnrichCgroupInfo(cgroupId uint64) (Container, error) {
    c.lock.Lock()
    defer c.lock.Unlock()

    var cont Container

    // 1. 查找 cgroup 信息
    info, ok := c.cgroupsMap[uint32(cgroupId)]
    if !ok {
        return cont, errfmt.Errorf("cgroup %d not found, won't enrich", cgroupId)
    }

    containerId := info.ContainerId
    if containerId == "" {
        // 不是容器，直接返回
        cont.ContainerId = ""
        return cont, nil
    }

    // 2. 检查是否已丰富化
    container := c.containerMap[containerId]

    // 特殊情况：minikube/kind 允许查询已删除的容器
    isMikubeOrKind := k8s.IsMinkube() || k8s.IsKind()
    if info.Dead && !isMikubeOrKind {
        return cont, errfmt.Errorf("container %s already deleted in path %s",
            containerId, info.Path)
    }

    if container.Image != "" {
        // 已丰富化（可能来自 control plane），直接返回
        return container, nil
    }

    // 3. 调用运行时 enricher
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()

    enrichRes, err := c.enricher.Get(ctx, containerId, container.Runtime)
    if err != nil {
        return cont, errfmt.WrapError(err)
    }

    // 4. 再次检查 cgroup 是否仍然存在（避免竞态条件）
    _, ok = c.cgroupsMap[uint32(cgroupId)]
    if ok {
        // 5. 更新容器信息
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
        c.cgroupsMap[uint32(cgroupId)] = info
        c.containerMap[containerId] = container
        cont = container
    }

    return cont, nil
}
```

---

## 5. eBPF 与用户空间集成

### 5.1 eBPF 容器状态 Map

**containers_map 定义** ([pkg/ebpf/c/maps.h:38](../../../pkg/ebpf/c/maps.h#L38)):

```c
// map cgroup id to container status {EXISTED, CREATED, STARTED}
struct containers_map {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);      // cgroup ID (lower 32 bits)
    __type(value, u8);     // container state
} containers_map SEC(".maps");

typedef struct containers_map containers_map_t;
```

**容器状态枚举** ([pkg/containers/containers.go:497](../../../pkg/containers/containers.go#L497)):

```go
const (
    containerExisted uint8 = iota + 1  // 1: 启动前已存在
    containerCreated                   // 2: 刚创建
    containerStarted                   // 3: 已启动
)
```

### 5.2 填充 eBPF Map

**启动时填充已存在的容器** ([pkg/containers/containers.go:505](../../../pkg/containers/containers.go#L505)):

```go
// PopulateBpfMap 将所有已存在的容器写入 eBPF map
// 这样 eBPF 程序可以正确区分新旧容器
func (c *Manager) PopulateBpfMap(bpfModule *libbpfgo.Module) error {
    containersMap, err := bpfModule.GetMap(c.bpfMapName)
    if err != nil {
        return errfmt.WrapError(err)
    }

    c.lock.RLock()
    defer c.lock.RUnlock()

    // 遍历所有容器根 cgroup
    for cgroupIdLsb, info := range c.cgroupsMap {
        if info.ContainerRoot {
            state := containerExisted
            err = containersMap.Update(
                unsafe.Pointer(&cgroupIdLsb),
                unsafe.Pointer(&state),
            )
        }
    }

    return errfmt.WrapError(err)
}
```

### 5.3 从 eBPF Map 移除容器

**容器删除时清理** ([pkg/containers/containers.go:524](../../../pkg/containers/containers.go#L524)):

```go
// RemoveFromBPFMap 从 eBPF map 移除容器
func (c *Manager) RemoveFromBPFMap(bpfModule *libbpfgo.Module, cgroupId uint64, hierarchyID uint32) error {
    // CGroup v1: 只处理默认控制器
    switch c.cgroups.GetDefaultCgroup().(type) {
    case *cgroup.CgroupV1:
        if c.cgroups.GetDefaultCgroupHierarchyID() != int(hierarchyID) {
            return nil
        }
    }

    containersMap, err := bpfModule.GetMap(c.bpfMapName)
    if err != nil {
        return errfmt.WrapError(err)
    }

    cgroupIdLsb := uint32(cgroupId)
    err = containersMap.DeleteKey(unsafe.Pointer(&cgroupIdLsb))

    // 忽略键不存在的错误（可能已被删除）
    if errors.Is(err, syscall.ENOENT) {
        logger.Debugw("cgroup already deleted", "error", err)
        return nil
    }

    return err
}
```

---

## 6. Kubernetes 集成

### 6.1 环境检测

**检测 K8s 开发环境** ([pkg/k8s/k8s.go:8](../../../pkg/k8s/k8s.go#L8)):

```go
// IsMinkube 检测是否运行在 Minikube 环境
func IsMinkube() bool {
    return strings.HasPrefix(os.Getenv("NODE_NAME"), "minikube")
}

// IsKind 检测是否运行在 Kind (Kubernetes in Docker) 环境
func IsKind() bool {
    return strings.HasPrefix(os.Getenv("NODE_NAME"), "kind")
}
```

**用途：**
- Minikube/Kind 环境中，容器可能在查询前已被删除
- 这些环境允许查询已标记为 `Dead` 的容器

### 6.2 标签提取

Kubernetes 通过容器标签传递 Pod 元数据：

```yaml
# Kubernetes 设置的容器标签（OCI runtime spec）
annotations:
  io.kubernetes.pod.name: "nginx-deployment-7d64c8b7d9-5x6zt"
  io.kubernetes.pod.namespace: "default"
  io.kubernetes.pod.uid: "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
  io.kubernetes.container.name: "nginx"
  io.kubernetes.container.type: "container"  # 或 "sandbox"
  io.kubernetes.container.hash: "12345678"
  io.kubernetes.container.restartCount: "0"
  io.kubernetes.container.terminationMessagePath: "/dev/termination-log"
  io.kubernetes.container.terminationMessagePolicy: "File"
```

### 6.3 Sandbox 容器识别

**什么是 Sandbox 容器？**
- Kubernetes 的每个 Pod 首先创建一个 **Pause/Sandbox 容器**
- 这个容器的作用：
  - 持有 Pod 的网络命名空间
  - 持有 Pod 的 IPC 命名空间
  - 其他容器共享这些命名空间
- Sandbox 容器标签：`io.kubernetes.container.type: "sandbox"`

**过滤逻辑：**
```go
if enrichRes.Sandbox {
    // 对于大多数检测规则，可能想跳过 Sandbox 容器
    // 因为它们不运行实际的应用代码
    return
}
```

---

## 7. 实战练习

### 练习 1：容器检测测试

**目标：** 验证 Tracee 的容器检测能力

```bash
# 1. 启动一个测试容器
docker run -d --name test-container nginx:latest

# 2. 获取容器 ID
CONTAINER_ID=$(docker ps -q --filter name=test-container)

# 3. 查看容器的 cgroup 路径
docker inspect $CONTAINER_ID | jq '.[0].HostConfig.CgroupParent'

# 4. 检查 cgroupfs 中的路径
sudo ls -la /sys/fs/cgroup/system.slice/docker-$CONTAINER_ID.scope

# 5. 获取 cgroup ID (inode 号)
sudo stat /sys/fs/cgroup/system.slice/docker-$CONTAINER_ID.scope | grep Inode

# 6. 使用 Tracee 追踪此容器
sudo ./dist/tracee \
    --scope container=$CONTAINER_ID \
    --events execve

# 7. 在容器中执行命令
docker exec test-container ls /

# 8. 观察 Tracee 输出，验证容器信息是否正确
```

**预期输出：**
```
TIME             UID    EVENT       CONTAINER        COMMAND          ARGS
14:23:45.678901  0      execve      test-container   ls               /
                 Container ID:    abc123...
                 Image:           nginx:latest
                 Runtime:         docker
```

### 练习 2：CGroup 路径解析

**目标：** 理解不同运行时的 cgroup 路径模式

**步骤：**

1. 创建测试工具：
```go
// test_cgroup_parser.go
package main

import (
    "fmt"
    "github.com/aquasecurity/tracee/pkg/containers"
)

func main() {
    testPaths := []string{
        "/system.slice/docker-abc123def456.scope",
        "/docker/abc123def456",
        "/kubepods/besteffort/pod123/abc123def456",
        "/system.slice/crio-abc123def456.scope",
        "/libpod-abc123def456.scope",
        "/actions_job/abc123def456",
    }

    for _, path := range testPaths {
        id, runtime, isRoot := containers.ParseContainerIdFromCgroupPath(path)
        fmt.Printf("Path: %s\n", path)
        fmt.Printf("  Container ID: %s\n", id)
        fmt.Printf("  Runtime: %s\n", runtime)
        fmt.Printf("  Is Root: %v\n\n", isRoot)
    }
}
```

2. 运行测试：
```bash
cd /home/work/tracee
go run test_cgroup_parser.go
```

### 练习 3：运行时 Socket 检测

**目标：** 检测系统中可用的容器运行时

```bash
# 1. 检查各运行时 socket
ls -lh /var/run/docker.sock 2>/dev/null && echo "Docker: Available"
ls -lh /var/run/containerd/containerd.sock 2>/dev/null && echo "containerd: Available"
ls -lh /var/run/crio/crio.sock 2>/dev/null && echo "CRI-O: Available"
ls -lh /var/run/podman/podman.sock 2>/dev/null && echo "Podman: Available"

# 2. 测试 Docker API
curl --unix-socket /var/run/docker.sock http://localhost/containers/json | jq

# 3. 创建测试程序检测运行时
cat > test_runtime_discovery.go <<'EOF'
package main

import (
    "fmt"
    "github.com/aquasecurity/tracee/pkg/containers/runtime"
)

func main() {
    sockets := runtime.Autodiscover(func(err error, rt runtime.RuntimeId, socket string) {
        fmt.Printf("Failed to register %s (%s): %v\n", rt, socket, err)
    })

    if sockets.Supports(runtime.Docker) {
        fmt.Println("✓ Docker runtime available")
    }
    if sockets.Supports(runtime.Containerd) {
        fmt.Println("✓ containerd runtime available")
    }
    if sockets.Supports(runtime.Crio) {
        fmt.Println("✓ CRI-O runtime available")
    }
    if sockets.Supports(runtime.Podman) {
        fmt.Println("✓ Podman runtime available")
    }
}
EOF

go run test_runtime_discovery.go
```

### 练习 4：Kubernetes Pod 追踪

**目标：** 在 Kubernetes 环境中追踪特定 Pod

**前提：** 需要 Kubernetes 集群（可用 Minikube 或 Kind）

```bash
# 1. 创建测试 Deployment
cat <<EOF | kubectl apply -f -
apiVersion: apps/v1
kind: Deployment
metadata:
  name: test-deployment
spec:
  replicas: 1
  selector:
    matchLabels:
      app: test
  template:
    metadata:
      labels:
        app: test
    spec:
      containers:
      - name: test-container
        image: nginx:latest
        command: ["sh", "-c", "while true; do date; sleep 5; done"]
EOF

# 2. 获取 Pod 名称
POD_NAME=$(kubectl get pods -l app=test -o jsonpath='{.items[0].metadata.name}')

# 3. 获取容器 ID
CONTAINER_ID=$(kubectl get pod $POD_NAME -o jsonpath='{.status.containerStatuses[0].containerID}' | cut -d'/' -f3)

# 4. 使用 Tracee 追踪（在 K8s 节点上运行）
sudo ./dist/tracee \
    --scope pod=$POD_NAME \
    --events execve,openat \
    --output json

# 5. 验证输出包含 Pod 元数据
# 应该看到类似：
# {
#   "container_id": "abc123...",
#   "container_name": "test-container",
#   "container_image": "nginx:latest",
#   "pod_name": "test-deployment-xxx-yyy",
#   "pod_namespace": "default",
#   "pod_uid": "...",
#   ...
# }
```

### 练习 5：容器生命周期追踪

**目标：** 观察容器从创建到删除的完整生命周期

```bash
# 1. 启动 Tracee 监听容器事件
sudo ./dist/tracee \
    --events cgroup_mkdir,cgroup_rmdir,container_create,container_remove \
    --output json > container_events.json &

TRACEE_PID=$!

# 2. 创建容器
docker run -d --name lifecycle-test alpine sleep 60

# 3. 等待一会儿
sleep 5

# 4. 删除容器
docker rm -f lifecycle-test

# 5. 停止 Tracee
sleep 2
kill $TRACEE_PID

# 6. 分析事件序列
cat container_events.json | jq -r '[.timestamp, .event_name, .container_id, .container_name] | @tsv'
```

**预期事件序列：**
```
1. cgroup_mkdir        - cgroup 目录创建
2. container_create    - 容器创建事件
3. (容器运行中的各种事件)
4. cgroup_rmdir        - cgroup 目录删除
5. container_remove    - 容器移除事件
```

### 练习 6：性能分析 - CGroup 查找优化

**目标：** 比较有无 subPath 提示时的查找性能

```go
// benchmark_cgroup_lookup.go
package main

import (
    "fmt"
    "time"
    "github.com/aquasecurity/tracee/common/cgroup"
)

func main() {
    cgroupId := uint64(12345)  // 替换为实际的 cgroup ID
    mountpoint := "/sys/fs/cgroup"

    // 测试1：无 subPath（全目录搜索）
    start := time.Now()
    _, _, err := cgroup.GetCgroupPath(mountpoint, cgroupId, "")
    elapsed1 := time.Since(start)
    if err != nil {
        fmt.Printf("Full search failed: %v\n", err)
    } else {
        fmt.Printf("Full search: %v\n", elapsed1)
    }

    // 测试2：有 subPath 提示
    subPath := "docker/abc123def456"  // 替换为实际路径
    start = time.Now()
    _, _, err = cgroup.GetCgroupPath(mountpoint, cgroupId, subPath)
    elapsed2 := time.Since(start)
    if err != nil {
        fmt.Printf("Hinted search failed: %v\n", err)
    } else {
        fmt.Printf("Hinted search: %v\n", elapsed2)
    }

    fmt.Printf("Speedup: %.2fx\n", float64(elapsed1)/float64(elapsed2))
}
```

---

## 8. 性能优化技巧

### 8.1 缓存策略

```go
// 优化1：cgroupsMap 缓存所有已知的 cgroup ID -> path 映射
// 避免重复的文件系统搜索

// 优化2：containerMap 缓存所有容器元数据
// 避免重复的运行时 API 调用

// 优化3：延迟删除（30秒过期时间）
// 处理事件乱序问题，避免过早删除仍在使用的容器信息
```

### 8.2 运行时查询优化

```go
// 优化1：已知运行时时直接查询，避免遍历
if containerRuntime != Unknown {
    return e.getFromKnownRuntime(ctx, containerId, containerRuntime)
}

// 优化2：设置查询超时（10秒）
ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
defer cancel()

// 优化3：检查是否已丰富化，避免重复查询
if container.Image != "" {
    return container, nil  // 已丰富化，直接返回
}
```

### 8.3 eBPF Map 优化

```c
// 优化1：使用 u32 存储 cgroup ID（低32位）
// 减少 map 内存使用，提升查找性能
__type(key, u32);  // 而非 u64

// 优化2：LRU 策略自动清理旧条目
// proc_info_map, task_info_map 使用 LRU_HASH
__uint(type, BPF_MAP_TYPE_LRU_HASH);
```

---

## 9. 常见问题排查

### 问题 1：容器未被检测到

**症状：** Tracee 事件中没有容器信息

**诊断步骤：**

```bash
# 1. 检查容器是否在运行
docker ps

# 2. 检查 cgroup 路径
CONTAINER_ID=<your-container-id>
docker inspect $CONTAINER_ID | jq '.[0].HostConfig.CgroupParent'

# 3. 验证 cgroupfs 中的目录
sudo find /sys/fs/cgroup -name "*$CONTAINER_ID*"

# 4. 检查 Tracee 日志
sudo ./dist/tracee --log debug --scope container=$CONTAINER_ID --events execve
```

**可能原因：**
1. CGroup 路径模式不匹配（新的运行时或版本）
2. Cgroupfs 未正确挂载
3. 容器使用了未知的运行时

### 问题 2：Kubernetes 元数据丢失

**症状：** pod_name, namespace 等字段为空

**诊断步骤：**

```bash
# 1. 检查容器标签
docker inspect <container-id> | jq '.[0].Config.Labels'

# 2. 检查运行时 socket
ls -lh /var/run/containerd/containerd.sock

# 3. 测试 CRI API
sudo crictl inspect <container-id> | jq .info.runtimeSpec.annotations
```

**可能原因：**
1. 容器标签未设置（非 K8s 环境）
2. 运行时 API 查询失败
3. 权限不足，无法访问 runtime socket

### 问题 3：容器事件延迟

**症状：** 容器启动后几秒才出现在 Tracee 输出中

**原因：**
- 容器丰富化需要查询运行时 API（可能耗时）
- 第一次查询时需要建立连接

**优化方案：**
```go
// 1. 预填充容器信息（启动时）
containers.Populate()

// 2. 异步丰富化
go func() {
    containers.EnrichCgroupInfo(cgroupId)
}()

// 3. 使用 control plane 推送容器信息（高级）
```

---

## 10. 进阶主题

### 10.1 嵌套容器检测

**场景：** Docker-in-Docker (DinD) 或 Kubernetes-in-Docker (KinD)

```
Host CGroup
  └─ Outer Container CGroup (Docker)
      └─ Inner Container CGroup (Docker-in-Docker)
```

**检测策略：**
```go
// parseContainerIdFromCgroupPath 从末尾向前搜索
// 返回最外层（最接近根）的容器 ID
for i := len(cgroupParts) - 1; i >= 0; i = i - 1 {
    // 找到第一个匹配的容器 ID 后立即返回
    // 这样可以获取最外层容器
}
```

### 10.2 Control Plane 集成

高级部署可以使用 Control Plane 主动推送容器信息：

```go
// 1. 监听 Kubernetes API Server
// 2. 容器创建时，提前推送元数据到 Tracee
// 3. 避免运行时 API 查询延迟

func (c *Manager) AddContainer(cont Container) error {
    c.lock.Lock()
    defer c.lock.Unlock()

    c.containerMap[cont.ContainerId] = cont
    return nil
}
```

### 10.3 自定义运行时支持

**添加新运行时的步骤：**

1. 定义运行时 ID：
```go
// pkg/containers/runtime/runtime.go
const (
    Docker RuntimeId = iota
    Containerd
    Crio
    Podman
    Garden
    YourNewRuntime  // 添加新运行时
)
```

2. 实现 Enricher 接口：
```go
type yourRuntimeEnricher struct {
    client YourRuntimeClient
}

func (e *yourRuntimeEnricher) Get(ctx context.Context, containerId string) (EnrichResult, error) {
    // 实现运行时查询逻辑
}
```

3. 注册到 Service：
```go
err := runtimeService.Register(YourNewRuntime, func(socket string) (ContainerEnricher, error) {
    return NewYourRuntimeEnricher(socket)
})
```

4. 添加 cgroup 路径模式匹配：
```go
// parseContainerIdFromCgroupPath 中添加
case strings.HasPrefix(id, "your-runtime-"):
    contRuntime = YourNewRuntime
    id = strings.TrimPrefix(id, "your-runtime-")
```

---

## 11. 下一步学习

完成本阶段后，你已经掌握了 Tracee 的容器感知系统！

**知识回顾：**
- ✅ CGroup v1/v2 的检测和解析
- ✅ 容器 ID 提取和运行时识别
- ✅ 多运行时适配器设计
- ✅ Kubernetes 元数据丰富化
- ✅ eBPF 与用户空间的集成

**推荐后续学习：**
1. **深入 eBPF 网络追踪**：学习 `pkg/ebpf/net` 中的网络事件处理
2. **性能分析**：研究 Tracee 的性能优化策略和 benchmark
3. **自定义签名开发**：基于容器元数据编写检测规则
4. **分布式追踪**：了解如何在多节点环境中部署 Tracee

**相关文档：**
- [Tracee 容器过滤文档](../../docs/filtering/container.md)
- [Kubernetes 部署指南](../../deploy/kubernetes/)
- [性能调优指南](../../docs/performance.md)

**贡献机会：**
- 添加新容器运行时支持（如 Kata Containers, gVisor）
- 优化 cgroup 路径解析性能
- 完善 Kubernetes DaemonSet 部署
- 编写更多容器安全检测签名

---

## 参考资料

### Linux CGroup 文档
- [Control Group v2](https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html)
- [Control Group v1](https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v1/)
- [cgroups(7) man page](https://man7.org/linux/man-pages/man7/cgroups.7.html)

### 容器运行时
- [containerd Documentation](https://containerd.io/docs/)
- [Docker Engine API](https://docs.docker.com/engine/api/)
- [CRI-O Documentation](https://cri-o.io/)
- [Kubernetes CRI](https://kubernetes.io/docs/concepts/architecture/cri/)

### Tracee 相关
- [Tracee GitHub Repository](https://github.com/aquasecurity/tracee)
- [Container Filters Documentation](../../docs/filtering/container.md)
- [Adding New Events Guide](../../docs/contributing/adding-events.md)

---

**恭喜你完成第六阶段的学习！**

你现在已经掌握了 Tracee 容器感知与集成的核心技术。继续探索 Tracee 的更多高级特性，并考虑为项目做出贡献！
