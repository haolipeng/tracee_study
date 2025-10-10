# Tracee 核心流程图集合

本文档包含 Tracee 学习过程中最重要的流程图，使用 Mermaid 格式绘制。

---

## 1. Tracee 整体架构图

```mermaid
graph TB
    subgraph "内核空间 (Kernel Space)"
        A[系统调用/LSM Hooks] --> B[eBPF Programs]
        B --> C[Perf Buffer]
        B --> D[BPF Maps]
    end

    subgraph "用户空间 (User Space)"
        C --> E[Event Decoder]
        E --> F[Event Sorter]
        F --> G[Event Processor]
        G --> H[Container Enricher]
        H --> I[Event Deriver]
        I --> J[Policy Engine]
        J --> K[Signature Engine]
        K --> L[Event Sink]
    end

    subgraph "外部系统"
        M[Container Runtime<br/>Docker/containerd]
        N[Proc FS]
        O[Output<br/>JSON/Table/Webhook]
    end

    D -.-> G
    G -.-> N
    H -.-> M
    L --> O

    style B fill:#ff6b6b
    style E fill:#4ecdc4
    style K fill:#ffe66d
```

---

## 2. 事件完整生命周期流程

```mermaid
sequenceDiagram
    participant K as 内核
    participant E as eBPF Program
    participant P as Perf Buffer
    participant D as Decoder
    participant S as Sorter
    participant Proc as Processor
    participant Enrich as Enricher
    participant Derive as Deriver
    participant Engine as Policy Engine
    participant Sig as Signature Engine
    participant Sink as Sink

    K->>E: 触发系统调用/Hook
    E->>E: 过滤检查 (Scope Filter)
    E->>P: 写入原始事件数据

    P->>D: 读取原始字节流
    D->>D: 解码二进制协议
    D->>S: 发送 Event 对象

    S->>S: 按时间戳排序
    S->>Proc: 有序事件流

    Proc->>Proc: 更新 Process Tree
    Proc->>Enrich: 传递事件

    Enrich->>Enrich: 查询容器信息
    Enrich->>Derive: 丰富化后的事件

    Derive->>Derive: 生成衍生事件
    Derive->>Engine: 所有事件

    Engine->>Engine: 策略匹配 (Bitmap)
    Engine->>Sig: 匹配的事件

    Sig->>Sig: 执行检测规则
    Sig->>Sink: 最终事件+告警

    Sink->>Sink: 格式化输出
```

---

## 3. eBPF 事件捕获流程

```mermaid
graph TD
    A[系统调用发生] --> B{进入/退出?}

    B -->|sys_enter| C[raw_tracepoint/sys_enter]
    B -->|sys_exit| D[raw_tracepoint/sys_exit]

    C --> E[检查 32/64 位兼容性]
    E --> F[sys_32_to_64_map 转换]
    F --> G[tail_call 到具体处理函数]

    G --> H[syscalls__sys_enter_init]
    H --> I[从 task_struct 提取上下文]
    I --> J{需要捕获此事件?}

    J -->|是| K[保存参数到 args_map]
    J -->|否| L[直接返回]

    K --> M[更新 proc_info_map]
    K --> N[更新 task_info_map]

    D --> O[syscalls__sys_exit_init]
    O --> P[从 args_map 读取参数]
    P --> Q[获取返回值]

    Q --> R[构造完整事件]
    R --> S[应用 eBPF 过滤器]

    S --> T{通过过滤?}
    T -->|是| U[bpf_perf_event_output]
    T -->|否| V[丢弃事件]

    U --> W[写入 Perf Buffer]
    W --> X[用户空间读取]

    style C fill:#ff6b6b
    style D fill:#ff6b6b
    style U fill:#4ecdc4
    style W fill:#4ecdc4
```

---

## 4. 策略过滤器应用流程

```mermaid
graph TB
    subgraph "eBPF 内核过滤 (Scope Filters)"
        A[事件产生] --> B{UID 过滤}
        B -->|不匹配| Z1[丢弃]
        B -->|匹配| C{PID 过滤}
        C -->|不匹配| Z2[丢弃]
        C -->|匹配| D{Cgroup 过滤}
        D -->|不匹配| Z3[丢弃]
        D -->|匹配| E{UTS 命名空间过滤}
        E -->|不匹配| Z4[丢弃]
        E -->|匹配| F{进程树过滤}
        F -->|不匹配| Z5[丢弃]
        F -->|匹配| G[发送到用户空间]
    end

    subgraph "用户空间过滤 (Data Filters)"
        G --> H[Policy Manager]
        H --> I{遍历所有策略}

        I --> J{Minimum 过滤<br/>事件ID必须启用}
        J -->|不匹配| Z6[跳过此策略]
        J -->|匹配| K{Maximum 过滤<br/>检查参数/返回值}

        K -->|不匹配| Z7[跳过此策略]
        K -->|匹配| L[添加到匹配位图]

        L --> M{还有策略?}
        M -->|是| I
        M -->|否| N{位图非空?}

        N -->|是| O[发送给 Signature Engine]
        N -->|否| Z8[丢弃事件]
    end

    style G fill:#4ecdc4
    style O fill:#ffe66d
```

---

## 5. 容器检测与丰富化流程

```mermaid
graph TB
    A[eBPF 捕获事件<br/>包含 cgroup_id] --> B{检查 cgroupsMap}

    B -->|存在| C[获取 CgroupDir 信息]
    B -->|不存在| D[调用 GetCgroupPath]

    D --> E[搜索 /sys/fs/cgroup]
    E --> F[匹配 inode 低32位]
    F --> G[解析 cgroup 路径]
    G --> H[提取容器 ID]
    H --> I[识别运行时类型]
    I --> J[更新 cgroupsMap]
    J --> C

    C --> K{容器 ID 为空?}
    K -->|是| L[非容器进程<br/>直接返回]
    K -->|否| M{检查 containerMap}

    M -->|已丰富化| N[直接返回容器信息]
    M -->|未丰富化| O[调用 EnrichCgroupInfo]

    O --> P{识别运行时}
    P -->|Docker| Q[Docker API 查询]
    P -->|containerd| R[containerd API 查询]
    P -->|CRI-O| S[CRI API 查询]
    P -->|Unknown| T[尝试所有 enricher]

    Q --> U[解析响应]
    R --> U
    S --> U
    T --> U

    U --> V[提取容器名称]
    U --> W[提取镜像信息]
    U --> X[提取 K8s 标签]

    V --> Y[更新 containerMap]
    W --> Y
    X --> Y

    Y --> Z[返回完整容器信息]

    style A fill:#ff6b6b
    style O fill:#4ecdc4
    style Y fill:#95e1d3
```

---

## 6. 签名引擎检测流程

```mermaid
graph LR
    A[事件到达] --> B[Signature Engine]

    B --> C{查找 eventSigs<br/>索引}

    C --> D[获取监听此事件<br/>的所有签名]

    D --> E{遍历签名列表}

    E --> F[签名 1: OnEvent]
    E --> G[签名 2: OnEvent]
    E --> H[签名 N: OnEvent]

    F --> I{检测到威胁?}
    G --> J{检测到威胁?}
    H --> K{检测到威胁?}

    I -->|是| L[Finding 1]
    J -->|是| M[Finding 2]
    K -->|是| N[Finding N]

    I -->|否| O[继续]
    J -->|否| O
    K -->|否| O

    L --> P[输出告警]
    M --> P
    N --> P

    O --> Q[处理下一个事件]

    style B fill:#ffe66d
    style P fill:#ff6b6b
```

---

## 7. Process Tree 维护流程

```mermaid
stateDiagram-v2
    [*] --> ProcessCreated: fork/clone/execve

    ProcessCreated --> AddToTree: 分配 ProcessInfo
    AddToTree --> UpdateParent: 设置父进程关系
    UpdateParent --> CacheProcFS: 从 /proc 读取信息

    CacheProcFS --> InTree: 添加到 LRU Cache

    InTree --> UpdateInfo: execve 事件
    UpdateInfo --> InTree: 更新可执行路径

    InTree --> UpdateInfo2: 其他事件
    UpdateInfo2 --> InTree: 更新统计信息

    InTree --> MarkExit: exit 事件
    MarkExit --> GracePeriod: 30秒宽限期

    GracePeriod --> RemoveFromTree: 超时
    RemoveFromTree --> [*]

    InTree --> Evicted: LRU 淘汰
    Evicted --> [*]

    note right of CacheProcFS
        读取 /proc/{pid}/stat
        读取 /proc/{pid}/cmdline
        读取 /proc/{pid}/cwd
    end note

    note right of GracePeriod
        防止事件乱序
        允许访问已退出进程信息
    end note
```

---

## 8. 事件排序器工作原理

```mermaid
graph TB
    subgraph "Per-CPU 输入流"
        A1[CPU 0 Events] --> B[Sorter]
        A2[CPU 1 Events] --> B
        A3[CPU 2 Events] --> B
        A4[CPU N Events] --> B
    end

    subgraph "排序缓冲区"
        B --> C[按 CPU 分组]
        C --> D[时间窗口缓冲<br/>默认 1000ms]

        D --> E{收集窗口<br/>事件}
    end

    subgraph "排序逻辑"
        E --> F[按时间戳排序]
        F --> G{检查乱序}

        G -->|顺序正确| H[输出事件]
        G -->|发现乱序| I[重新排序]
        I --> H
    end

    subgraph "输出流"
        H --> J[有序事件流]
        J --> K[下游处理器]
    end

    style D fill:#4ecdc4
    style F fill:#ffe66d
    style J fill:#95e1d3
```

---

## 9. CGroup 路径解析算法

```mermaid
graph TD
    A[输入: cgroup_id, subPath] --> B[初始化栈<br/>stack = rootDir]

    B --> C{栈非空?}
    C -->|否| Z[未找到<br/>返回 ErrNotExist]

    C -->|是| D[弹出目录]
    D --> E[读取目录内容]

    E --> F{遍历所有条目}
    F -->|下一个| G{是目录?}

    G -->|否| F
    G -->|是| H[构造完整路径]

    H --> I{匹配 subPath?}
    I -->|否| J[压入栈继续搜索]
    I -->|是| K[stat 获取 inode]

    J --> F

    K --> L{低32位匹配?}
    L -->|否| F
    L -->|是| M[提取 ctime]

    M --> N[返回路径和时间]

    F -->|遍历完成| C

    style A fill:#4ecdc4
    style L fill:#ffe66d
    style N fill:#95e1d3
```

---

## 10. 衍生事件生成流程

```mermaid
graph LR
    A[原始事件] --> B{事件类型?}

    B -->|sched_process_exec| C[Derive: ProcessExecuteFailed<br/>如果 retval < 0]

    B -->|security_socket_connect| D[Derive: NetPacketIPv4/IPv6<br/>网络连接事件]

    B -->|security_socket_sendmsg| E[Derive: NetPacketICMP<br/>如果是 ICMP]

    B -->|vfs_write| F[Derive: MagicWrite<br/>检测文件魔数修改]

    B -->|security_bprm_check| G[Derive: SymbolsLoaded<br/>可执行文件符号表]

    B -->|cgroup_mkdir| H[Derive: ContainerCreate<br/>容器创建]

    B -->|cgroup_rmdir| I[Derive: ContainerRemove<br/>容器删除]

    C --> J[发送衍生事件]
    D --> J
    E --> J
    F --> J
    G --> J
    H --> J
    I --> J

    J --> K[继续事件流]

    style B fill:#4ecdc4
    style J fill:#ffe66d
```

---

## 11. Bitmap 策略匹配优化

```mermaid
graph TB
    subgraph "策略位图表示"
        A[64个策略<br/>用 uint64 位图表示]
        A --> B[Bit 0 = Policy 0]
        A --> C[Bit 1 = Policy 1]
        A --> D[Bit 63 = Policy 63]
    end

    subgraph "事件匹配流程"
        E[Event: execve] --> F[初始化 matched = 0]

        F --> G{遍历策略 0-63}
        G --> H{Policy 0 匹配?}
        H -->|是| I[matched |= 1 << 0]
        H -->|否| J[继续]

        I --> K{Policy 1 匹配?}
        K -->|是| L[matched |= 1 << 1]
        K -->|否| J

        J --> M[...检查所有策略]
        L --> M

        M --> N{matched != 0?}
        N -->|是| O[发送给签名引擎]
        N -->|否| P[丢弃事件]
    end

    subgraph "性能优势"
        Q[单个 uint64 操作]
        R[CPU 缓存友好]
        S[位运算极快]
    end

    style A fill:#4ecdc4
    style O fill:#ffe66d
```

---

## 12. 容器运行时适配器架构

```mermaid
graph TB
    subgraph "Container Manager"
        A[容器事件] --> B[提取 Container ID<br/>和 Runtime 类型]
    end

    B --> C[Runtime Service]

    subgraph "多运行时支持"
        C --> D{已知运行时?}

        D -->|Docker| E[Docker Enricher]
        D -->|containerd| F[containerd Enricher]
        D -->|CRI-O| G[CRI-O Enricher]
        D -->|Podman| H[Podman Enricher]
        D -->|Unknown| I[尝试所有 Enricher]
    end

    subgraph "外部 API"
        E --> J[Docker Socket<br/>/var/run/docker.sock]
        F --> K[containerd Socket<br/>/var/run/containerd/containerd.sock]
        G --> L[CRI-O Socket<br/>/var/run/crio/crio.sock]
        H --> M[Podman Socket<br/>/var/run/podman/podman.sock]
    end

    J --> N[查询容器元数据]
    K --> N
    L --> N
    M --> N

    N --> O[解析响应]
    O --> P[提取容器名称]
    O --> Q[提取镜像信息]
    O --> R[提取 K8s 标签]

    P --> S[EnrichResult]
    Q --> S
    R --> S

    S --> T[更新 containerMap]

    style C fill:#4ecdc4
    style S fill:#95e1d3
```

---

## 13. 自定义签名开发流程

```mermaid
sequenceDiagram
    participant Dev as 开发者
    participant Sig as Signature 实现
    participant Eng as Signature Engine
    participant Evt as Event Stream

    Dev->>Sig: 1. 实现 Signature 接口
    Note over Sig: GetMetadata()<br/>GetSelectedEvents()<br/>Init()<br/>OnEvent()<br/>OnSignal()<br/>Close()

    Dev->>Sig: 2. 定义检测逻辑
    Note over Sig: 在 OnEvent() 中<br/>分析事件参数<br/>检测威胁模式

    Dev->>Eng: 3. 注册签名
    Eng->>Eng: 4. 构建事件索引
    Note over Eng: eventSigs map<br/>event_id -> []Signature

    Evt->>Eng: 5. 事件到达
    Eng->>Eng: 6. 查找索引
    Eng->>Sig: 7. 调用 OnEvent()

    Sig->>Sig: 8. 执行检测

    alt 检测到威胁
        Sig->>Eng: 9a. 返回 Finding
        Eng->>Evt: 10a. 输出告警
    else 未检测到
        Sig->>Eng: 9b. 返回 nil
        Eng->>Evt: 10b. 继续处理
    end
```

---

## 14. Tracee 启动初始化流程

```mermaid
graph TD
    A[main] --> B[解析命令行参数]
    B --> C[加载配置文件]

    C --> D[初始化 CGroup 管理器]
    D --> E[检测 CGroup v1/v2]
    E --> F[挂载 cgroupfs]

    F --> G[初始化 Container Manager]
    G --> H[自动发现容器运行时]
    H --> I[注册 Runtime Enrichers]

    I --> J[加载 eBPF 程序]
    J --> K[编译或加载 BPF 对象]
    K --> L[创建 BPF Maps]

    L --> M[初始化 Policy Manager]
    M --> N[解析策略 YAML]
    N --> O[构建过滤器]

    O --> P[初始化 Signature Engine]
    P --> Q[加载所有签名]
    Q --> R[构建事件索引]

    R --> S[Populate Process Tree]
    S --> T[从 /proc 读取现有进程]

    T --> U[Populate Container Map]
    U --> V[从 cgroupfs 读取现有容器]

    V --> W[Attach eBPF Programs]
    W --> X[附加到 Tracepoints/LSM Hooks]

    X --> Y[启动事件处理 Pipeline]
    Y --> Z[开始追踪]

    style A fill:#4ecdc4
    style J fill:#ff6b6b
    style P fill:#ffe66d
    style Z fill:#95e1d3
```

---

## 15. DNS 缓存工作流程

```mermaid
graph TB
    subgraph "DNS 请求捕获"
        A[security_socket_sendmsg] --> B{检查目标端口}
        B -->|53| C[解析 DNS 查询]
        B -->|其他| Z1[忽略]

        C --> D[提取查询域名]
        D --> E[生成查询 Key]
        E --> F[存入 dnsCache]
    end

    subgraph "DNS 响应捕获"
        G[security_socket_recvmsg] --> H{来源端口53?}
        H -->|是| I[解析 DNS 响应]
        H -->|否| Z2[忽略]

        I --> J[提取响应 IP]
        J --> K[查找对应查询]
        K --> L{找到匹配?}

        L -->|是| M[创建 domain->IP 映射]
        L -->|否| Z3[忽略]

        M --> N[存入 Tree 结构]
    end

    subgraph "反向查询"
        O[网络事件<br/>包含目标 IP] --> P[LookupByIP]
        P --> Q[Tree 搜索]

        Q --> R{找到域名?}
        R -->|是| S[丰富化事件<br/>添加域名字段]
        R -->|否| T[保持原样]
    end

    F -.->|关联| K
    N -.->|查询| Q

    style C fill:#4ecdc4
    style M fill:#ffe66d
    style S fill:#95e1d3
```

---

## 使用建议

### 如何查看这些图表？

1. **在 GitHub 上查看**：GitHub 原生支持 Mermaid 渲染
   ```bash
   git add docs/learning/diagrams.md
   git commit -m "docs: add mermaid diagrams"
   git push
   ```

2. **在 VSCode 中查看**：安装 Mermaid 插件
   - 插件名称：`Markdown Preview Mermaid Support`
   - 打开文件后使用预览功能（Ctrl+Shift+V）

3. **在线编辑器**：
   - [Mermaid Live Editor](https://mermaid.live/)
   - 复制图表代码进行编辑和导出

4. **生成图片**：使用 mermaid-cli
   ```bash
   npm install -g @mermaid-js/mermaid-cli
   mmdc -i diagrams.md -o diagrams.pdf
   ```

### 图表索引

- **图1-4**：架构和整体流程（适合初学者）
- **图5-7**：核心子系统详解（容器、签名、进程树）
- **图8-11**：算法和优化细节（排序、解析、衍生、位图）
- **图12-15**：高级特性（运行时适配、签名开发、初始化、DNS）

### 学习路径建议

```
第一周：图1 → 图2 → 图14
第二周：图3 → 图4 → 图8
第三周：图5 → 图9 → 图12
第四周：图6 → 图7 → 图13
```

---

**提示：** 这些图表对应学习路线图的 6 个阶段文档。建议结合具体代码和文档一起学习。
