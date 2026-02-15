# Tracee 源代码学习指南 - 第五阶段：策略与检测引擎

> **学习目标**：深入理解策略系统和签名检测引擎的设计与实现
> **预计时间**：3-4 天
> **前置知识**：完成前四阶段学习，理解事件流水线

---

## 📋 目录

1. [策略系统概览](#1-策略系统概览)
2. [Policy 结构详解](#2-policy-结构详解)
3. [过滤器系统](#3-过滤器系统)
4. [策略管理器](#4-策略管理器)
5. [签名检测引擎](#5-签名检测引擎)
6. [自定义签名开发](#6-自定义签名开发)
7. [实践练习](#7-实践练习)

---

## 1. 策略系统概览

### 1.1 策略架构

```
┌─────────────────────────────────────────────────────────────────┐
│                    Tracee 策略系统架构                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  策略定义层 (YAML/CLI)                                            │
│  ┌────────────────────────────────────────────────────────────┐│
│  │  policy.yaml                                                ││
│  │  ┌──────────────────────────────────────────────────────┐  ││
│  │  │ apiVersion: tracee.aquasecurity.github.io/v1beta1    │  ││
│  │  │ kind: Policy                                         │  ││
│  │  │ metadata:                                            │  ││
│  │  │   name: my-policy                                    │  ││
│  │  │ spec:                                                │  ││
│  │  │   scope:                                             │  ││
│  │  │     - uid=0                                          │  ││
│  │  │     - container=new                                  │  ││
│  │  │   rules:                                             │  ││
│  │  │     - event: security_file_open                      │  ││
│  │  │       filters:                                       │  ││
│  │  │         - args.pathname=/etc/shadow                  │  ││
│  │  └──────────────────────────────────────────────────────┘  ││
│  └────────────────────────────────────────────────────────────┘│
│                           │                                      │
│                           ▼                                      │
│  策略解析层 (policy.Manager)                                      │
│  ┌────────────────────────────────────────────────────────────┐│
│  │  Policy Parser & Validator                                 ││
│  │  • YAML → Policy struct                                    ││
│  │  • 验证规则合法性                                           ││
│  │  • 构建过滤器链                                             ││
│  └────────────────┬───────────────────────────────────────────┘│
│                   │                                              │
│                   ▼                                              │
│  策略管理层 (Policy Manager)                                      │
│  ┌────────────────────────────────────────────────────────────┐│
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐    ││
│  │  │  Policies    │  │  EventFlags  │  │  Snapshots   │    ││
│  │  │  策略存储     │  │  事件标志     │  │  快照管理     │    ││
│  │  └──────────────┘  └──────────────┘  └──────────────┘    ││
│  └────────────────┬───────────────────────────────────────────┘│
│                   │                                              │
│                   ▼                                              │
│  过滤执行层                                                       │
│  ┌────────────────────────────────────────────────────────────┐│
│  │  eBPF 侧过滤 (内核态)          用户空间过滤                  ││
│  │  ┌──────────────────┐         ┌──────────────────┐        ││
│  │  │  Scope Filter    │         │  Data Filter     │        ││
│  │  │  • UID/GID       │         │  • 参数值        │        ││
│  │  │  • PID/TID       │         │  • 返回值        │        ││
│  │  │  • Container ID  │         │  • 复杂逻辑      │        ││
│  │  │  • Namespace     │         │                  │        ││
│  │  └──────────────────┘         └──────────────────┘        ││
│  └─────────────────────────────────────────────────────────────┘│
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### 1.2 策略工作流程

```
用户定义策略 (YAML/CLI)
         │
         ▼
    解析和验证
         │
         ├─────────────────────────────────────┐
         │                                     │
         ▼                                     ▼
   构建 Scope Filters              构建 Event Filters
   (进程、容器、UID等)               (事件类型、参数等)
         │                                     │
         └──────────────┬──────────────────────┘
                        │
                        ▼
              Policy Manager 存储
                        │
                        ├──────────────────┬──────────────────┐
                        │                  │                  │
                        ▼                  ▼                  ▼
                  eBPF Maps          事件流水线          签名引擎
                  (内核过滤)         (用户空间过滤)      (检测规则)
```

---

## 2. Policy 结构详解

### 2.1 Policy 核心结构 - [pkg/policy/policy.go](pkg/policy/policy.go)

```go
// Policy 定义单个策略
type Policy struct {
    // ========== 基本信息 ==========
    ID   int    // 策略 ID (唯一)
    Name string // 策略名称

    // ========== Scope 过滤器 (作用域) ==========
    UIDFilter    *filters.NumericFilter[uint32] // 用户 ID 过滤
    PIDFilter    *filters.NumericFilter[uint32] // 进程 ID 过滤
    NewPidFilter *filters.BoolFilter             // 是否为新进程
    MntNSFilter  *filters.NumericFilter[uint64]  // Mount namespace 过滤
    PidNSFilter  *filters.NumericFilter[uint64]  // PID namespace 过滤
    UTSFilter    *filters.StringFilter           // UTS namespace (主机名)
    CommFilter   *filters.StringFilter           // 进程名过滤

    // ========== 容器过滤器 ==========
    ContFilter    *filters.BoolFilter   // 是否在容器中
    NewContFilter *filters.BoolFilter   // 是否为新容器
    ContIDFilter  *filters.StringFilter // 容器 ID 列表过滤

    // ========== 高级过滤器 ==========
    ProcessTreeFilter *filters.ProcessTreeFilter // 进程树过滤
    BinaryFilter      *filters.BinaryFilter      // 二进制文件过滤

    // ========== 策略行为 ==========
    Follow bool // 是否跟踪子进程

    // ========== 事件规则 ==========
    Rules map[events.ID]RuleData // 事件 ID → 规则数据
}

// RuleData 定义单个事件的规则
type RuleData struct {
    EventID     events.ID                  // 事件 ID
    ScopeFilter *filters.ScopeFilter       // 作用域过滤 (二次检查)
    DataFilter  *filters.DataFilter        // 数据过滤 (参数、返回值)
    RetFilter   *filters.NumericFilter[int64] // 返回值过滤
}
```

### 2.2 Policy 创建示例

#### 通过 YAML 定义

```yaml
# policy.yaml
apiVersion: tracee.aquasecurity.github.io/v1beta1
kind: Policy
metadata:
  name: monitor-sensitive-files
  annotations:
    description: 监控敏感文件访问
spec:
  # ========== Scope (作用域) ==========
  scope:
    - uid=0                    # 仅监控 root 用户
    - container=new            # 仅监控新容器
    - comm=bash,sh             # 仅监控 bash/sh 进程

  # ========== Rules (事件规则) ==========
  rules:
    # 规则1: 监控 /etc/shadow 访问
    - event: security_file_open
      filters:
        - args.pathname=/etc/shadow
        - args.pathname=/etc/passwd

    # 规则2: 监控特权进程执行
    - event: sched_process_exec
      filters:
        - args.argv~*sudo*       # 命令行包含 sudo

    # 规则3: 监控网络连接
    - event: security_socket_connect
      filters:
        - args.remote_addr.port>1024  # 端口大于1024
```

#### 通过 Go 代码创建

```go
// 创建新策略
policy := policy.NewPolicy()
policy.ID = 1
policy.Name = "monitor-root-activity"

// ========== 配置 Scope 过滤 ==========
// 仅监控 UID=0 (root)
policy.UIDFilter.Parse("=0")
policy.UIDFilter.Enable()

// 仅监控新容器
policy.NewContFilter.Parse("=true")
policy.NewContFilter.Enable()

// ========== 配置事件规则 ==========
// 规则1: 监控文件打开
fileOpenRule := policy.RuleData{
    EventID: events.SecurityFileOpen,
    DataFilter: filters.NewDataFilter().
        AddPathname("/etc/shadow").
        AddPathname("/etc/passwd"),
}
policy.Rules[events.SecurityFileOpen] = fileOpenRule

// 规则2: 监控进程执行
execRule := policy.RuleData{
    EventID: events.SchedProcessExec,
}
policy.Rules[events.SchedProcessExec] = execRule
```

---

## 3. 过滤器系统

### 3.1 过滤器类型层次

```
Filter (接口)
    │
    ├── NumericFilter[T]          # 数值过滤器
    │   ├── UInt32Filter         # uint32 (UID, PID)
    │   ├── UInt64Filter         # uint64 (Namespace)
    │   └── Int64Filter          # int64 (返回值)
    │
    ├── StringFilter             # 字符串过滤器
    │   ├── 精确匹配
    │   ├── 前缀匹配 (~prefix*)
    │   └── 包含匹配 (*substring*)
    │
    ├── BoolFilter               # 布尔过滤器
    │   ├── true
    │   └── false
    │
    ├── ScopeFilter              # 作用域过滤器 (组合)
    │
    ├── DataFilter               # 数据过滤器 (参数值)
    │
    ├── ProcessTreeFilter        # 进程树过滤器
    │
    └── BinaryFilter             # 二进制文件过滤器
```

### 3.2 NumericFilter 实现

```go
// NumericFilter 泛型数值过滤器
type NumericFilter[T constraints.Integer] struct {
    enabled  bool
    equal    map[T]struct{}    // 等于列表
    notEqual map[T]struct{}    // 不等于列表
    greater  map[T]struct{}    // 大于列表
    less     map[T]struct{}    // 小于列表
    greaterEqual map[T]struct{} // 大于等于列表
    lessEqual    map[T]struct{} // 小于等于列表
}

// Parse 解析过滤器表达式
func (f *NumericFilter[T]) Parse(operatorAndValues string) error {
    // 支持格式:
    // "=123"         → equal
    // "!=123"        → notEqual
    // ">123"         → greater
    // "<123"         → less
    // ">=123"        → greaterEqual
    // "<=123"        → lessEqual
    // "=123,456,789" → 多个值

    // 解析操作符
    var operator Operator
    var valueStr string

    if strings.HasPrefix(operatorAndValues, ">=") {
        operator = GreaterEqual
        valueStr = operatorAndValues[2:]
    } else if strings.HasPrefix(operatorAndValues, "<=") {
        operator = LessEqual
        valueStr = operatorAndValues[2:]
    } else if strings.HasPrefix(operatorAndValues, "!=") {
        operator = NotEqual
        valueStr = operatorAndValues[2:]
    } else if strings.HasPrefix(operatorAndValues, ">") {
        operator = Greater
        valueStr = operatorAndValues[1:]
    } else if strings.HasPrefix(operatorAndValues, "<") {
        operator = Lower
        valueStr = operatorAndValues[1:]
    } else if strings.HasPrefix(operatorAndValues, "=") {
        operator = Equal
        valueStr = operatorAndValues[1:]
    } else {
        return fmt.Errorf("invalid operator")
    }

    // 解析值列表
    values := strings.Split(valueStr, ",")
    for _, v := range values {
        val, err := strconv.ParseInt(v, 10, 64)
        if err != nil {
            return err
        }

        // 添加到对应的集合
        switch operator {
        case Equal:
            f.equal[T(val)] = struct{}{}
        case NotEqual:
            f.notEqual[T(val)] = struct{}{}
        case Greater:
            f.greater[T(val)] = struct{}{}
        case Less:
            f.less[T(val)] = struct{}{}
        case GreaterEqual:
            f.greaterEqual[T(val)] = struct{}{}
        case LessEqual:
            f.lessEqual[T(val)] = struct{}{}
        }
    }

    return nil
}

// Filter 检查值是否通过过滤
func (f *NumericFilter[T]) Filter(val interface{}) bool {
    if !f.enabled {
        return true // 未启用，全部通过
    }

    v, ok := val.(T)
    if !ok {
        return false // 类型不匹配
    }

    // ========== 检查 NotEqual ==========
    if _, exists := f.notEqual[v]; exists {
        return false // 在黑名单中
    }

    // ========== 检查 Equal ==========
    if len(f.equal) > 0 {
        if _, exists := f.equal[v]; !exists {
            return false // 不在白名单中
        }
    }

    // ========== 检查范围过滤 ==========
    for threshold := range f.greater {
        if v <= threshold {
            return false
        }
    }

    for threshold := range f.less {
        if v >= threshold {
            return false
        }
    }

    for threshold := range f.greaterEqual {
        if v < threshold {
            return false
        }
    }

    for threshold := range f.lessEqual {
        if v > threshold {
            return false
        }
    }

    return true // 通过所有检查
}
```

### 3.3 StringFilter 实现

```go
// StringFilter 字符串过滤器
type StringFilter struct {
    enabled  bool
    equal    map[string]struct{} // 精确匹配
    notEqual map[string]struct{} // 不等于
    prefixes []string            // 前缀匹配
    suffixes []string            // 后缀匹配
    contains []string            // 包含匹配
}

// Parse 解析字符串过滤表达式
func (f *StringFilter) Parse(operatorAndValues string) error {
    // 支持格式:
    // "=bash"          → 精确匹配
    // "!=python"       → 不等于
    // "~bash*"         → 前缀匹配
    // "~*.py"          → 后缀匹配
    // "~*python*"      → 包含匹配

    if strings.HasPrefix(operatorAndValues, "!=") {
        // 不等于
        values := strings.Split(operatorAndValues[2:], ",")
        for _, v := range values {
            f.notEqual[v] = struct{}{}
        }
    } else if strings.HasPrefix(operatorAndValues, "=") {
        // 精确匹配
        values := strings.Split(operatorAndValues[1:], ",")
        for _, v := range values {
            f.equal[v] = struct{}{}
        }
    } else if strings.HasPrefix(operatorAndValues, "~") {
        // 模式匹配
        pattern := operatorAndValues[1:]

        if strings.HasPrefix(pattern, "*") && strings.HasSuffix(pattern, "*") {
            // *substring* - 包含匹配
            f.contains = append(f.contains, strings.Trim(pattern, "*"))
        } else if strings.HasPrefix(pattern, "*") {
            // *suffix - 后缀匹配
            f.suffixes = append(f.suffixes, strings.TrimPrefix(pattern, "*"))
        } else if strings.HasSuffix(pattern, "*") {
            // prefix* - 前缀匹配
            f.prefixes = append(f.prefixes, strings.TrimSuffix(pattern, "*"))
        } else {
            // 无通配符，当作精确匹配
            f.equal[pattern] = struct{}{}
        }
    }

    return nil
}

// Filter 检查字符串是否通过过滤
func (f *StringFilter) Filter(val interface{}) bool {
    if !f.enabled {
        return true
    }

    str, ok := val.(string)
    if !ok {
        return false
    }

    // ========== 检查 NotEqual ==========
    if _, exists := f.notEqual[str]; exists {
        return false
    }

    // ========== 检查 Equal ==========
    if len(f.equal) > 0 {
        if _, exists := f.equal[str]; !exists {
            // 检查模式匹配
            matched := false

            // 前缀匹配
            for _, prefix := range f.prefixes {
                if strings.HasPrefix(str, prefix) {
                    matched = true
                    break
                }
            }

            // 后缀匹配
            if !matched {
                for _, suffix := range f.suffixes {
                    if strings.HasSuffix(str, suffix) {
                        matched = true
                        break
                    }
                }
            }

            // 包含匹配
            if !matched {
                for _, substr := range f.contains {
                    if strings.Contains(str, substr) {
                        matched = true
                        break
                    }
                }
            }

            if !matched {
                return false
            }
        }
    }

    return true
}
```

### 3.4 DataFilter (参数过滤器)

```go
// DataFilter 用于过滤事件参数值
type DataFilter struct {
    filters map[string]Filter // 参数名 → 过滤器
}

// AddFilter 添加参数过滤
func (df *DataFilter) AddFilter(argName string, filter Filter) {
    df.filters[argName] = filter
}

// Filter 检查事件参数是否通过过滤
func (df *DataFilter) Filter(event *trace.Event) bool {
    // 遍历所有参数过滤器
    for argName, filter := range df.filters {
        // 查找事件参数
        argValue := df.findArgValue(event, argName)
        if argValue == nil {
            return false // 参数不存在
        }

        // 应用过滤器
        if !filter.Filter(argValue) {
            return false // 过滤失败
        }
    }

    return true // 所有过滤器都通过
}

// findArgValue 查找事件参数值
func (df *DataFilter) findArgValue(event *trace.Event, argPath string) interface{} {
    // 支持嵌套路径，如 "args.pathname" 或 "args.remote_addr.ip"
    parts := strings.Split(argPath, ".")

    if parts[0] != "args" {
        return nil
    }

    if len(parts) < 2 {
        return nil
    }

    argName := parts[1]

    // 查找参数
    for _, arg := range event.Args {
        if arg.Name == argName {
            // 如果有嵌套路径，递归查找
            if len(parts) > 2 {
                return df.findNestedValue(arg.Value, parts[2:])
            }
            return arg.Value
        }
    }

    return nil
}

// findNestedValue 递归查找嵌套值
func (df *DataFilter) findNestedValue(val interface{}, path []string) interface{} {
    if len(path) == 0 {
        return val
    }

    // 支持 map 和 struct
    switch v := val.(type) {
    case map[string]interface{}:
        nextVal, exists := v[path[0]]
        if !exists {
            return nil
        }
        return df.findNestedValue(nextVal, path[1:])

    case trace.SockAddr:
        // 特殊处理 sockaddr
        switch path[0] {
        case "ip":
            return v.IP
        case "port":
            return v.Port
        }
    }

    return nil
}
```

---

## 4. 策略管理器

### 4.1 Manager 结构 - [pkg/policy/policy_manager.go](pkg/policy/policy_manager.go)

```go
// Manager 线程安全的策略管理器
type Manager struct {
    mu              sync.RWMutex             // 读写锁
    cfg             ManagerConfig            // 配置
    evtsDepsManager *dependencies.Manager    // 事件依赖管理器
    ps              *policies                // 策略集合
    rules           map[events.ID]*eventFlags // 事件 ID → 标志
}

// eventFlags 存储事件的策略标志
type eventFlags struct {
    Submit uint64 // 哪些策略需要提交此事件 (位图)
    Emit   uint64 // 哪些策略需要发射此事件 (位图)
}

// policies 存储所有策略
type policies struct {
    mu       sync.RWMutex
    policies map[int]*Policy // 策略 ID → 策略
    version  uint16          // 版本号 (用于快照)
}
```

### 4.2 策略创建和管理

```go
// NewManager 创建策略管理器
func NewManager(
    cfg ManagerConfig,
    depsManager *dependencies.Manager,
    initialPolicies ...*Policy,
) (*Manager, error) {
    ps := NewPolicies()

    // ========== 添加初始策略 ==========
    for _, p := range initialPolicies {
        if err := ps.set(p); err != nil {
            logger.Errorw("failed to set initial policy", "error", err)
        }
    }

    m := &Manager{
        mu:              sync.RWMutex{},
        cfg:             cfg,
        evtsDepsManager: depsManager,
        ps:              ps,
        rules:           make(map[events.ID]*eventFlags),
    }

    // ========== 初始化 ==========
    if err := m.initialize(); err != nil {
        return nil, errfmt.Errorf("failed to initialize: %s", err)
    }

    return m, nil
}

// initialize 初始化策略管理器
func (m *Manager) initialize() error {
    m.mu.Lock()
    defer m.mu.Unlock()

    // ========== 订阅依赖处理器 ==========
    m.subscribeDependencyHandlers()

    // ========== 计算事件规则 ==========
    if err := m.computeRules(); err != nil {
        return err
    }

    return nil
}

// computeRules 计算所有策略的事件规则
func (m *Manager) computeRules() error {
    m.rules = make(map[events.ID]*eventFlags)

    // 遍历所有策略
    for policyID, policy := range m.ps.policies {
        // 遍历策略中的所有规则
        for eventID := range policy.Rules {
            // 获取或创建 eventFlags
            if m.rules[eventID] == nil {
                m.rules[eventID] = &eventFlags{
                    Submit: 0,
                    Emit:   0,
                }
            }

            // 设置策略位
            policyBit := uint64(1 << policyID)
            m.rules[eventID].Submit |= policyBit
            m.rules[eventID].Emit |= policyBit

            // ========== 注册事件依赖 ==========
            m.evtsDepsManager.SelectEvent(eventID)
        }
    }

    return nil
}
```

### 4.3 策略匹配

```go
// MatchPolicy 检查事件是否匹配任何策略
func (m *Manager) MatchPolicy(event *trace.Event) uint64 {
    m.mu.RLock()
    defer m.mu.RUnlock()

    var matchedPolicies uint64 = 0

    // 获取事件的规则标志
    flags, exists := m.rules[event.EventID]
    if !exists {
        return 0 // 没有策略监控此事件
    }

    // 遍历所有可能的策略
    for policyID := 0; policyID < 64; policyID++ {
        policyBit := uint64(1 << policyID)

        // 检查此策略是否监控此事件
        if (flags.Submit & policyBit) == 0 {
            continue
        }

        // 获取策略
        policy, err := m.ps.get(policyID)
        if err != nil {
            continue
        }

        // ========== 应用 Scope 过滤 ==========
        if !m.matchScope(event, policy) {
            continue
        }

        // ========== 应用 Data 过滤 ==========
        ruleData, exists := policy.Rules[event.EventID]
        if exists && ruleData.DataFilter != nil {
            if !ruleData.DataFilter.Filter(event) {
                continue
            }
        }

        // 策略匹配成功
        matchedPolicies |= policyBit
    }

    return matchedPolicies
}

// matchScope 检查事件是否匹配策略的作用域
func (m *Manager) matchScope(event *trace.Event, policy *Policy) bool {
    // ========== UID 过滤 ==========
    if policy.UIDFilter.Enabled() {
        if !policy.UIDFilter.Filter(uint32(event.UserID)) {
            return false
        }
    }

    // ========== PID 过滤 ==========
    if policy.PIDFilter.Enabled() {
        if !policy.PIDFilter.Filter(uint32(event.ProcessID)) {
            return false
        }
    }

    // ========== 进程名过滤 ==========
    if policy.CommFilter.Enabled() {
        if !policy.CommFilter.Filter(event.ProcessName) {
            return false
        }
    }

    // ========== 容器过滤 ==========
    if policy.ContFilter.Enabled() {
        inContainer := event.Container.ID != ""
        if !policy.ContFilter.Filter(inContainer) {
            return false
        }
    }

    // ========== 容器 ID 过滤 ==========
    if policy.ContIDFilter.Enabled() {
        if !policy.ContIDFilter.Filter(event.Container.ID) {
            return false
        }
    }

    // ... 其他 Scope 过滤

    return true // 所有 Scope 过滤都通过
}
```

---

## 5. 签名检测引擎

### 5.1 引擎架构

```
┌─────────────────────────────────────────────────────────────────┐
│                    Signature Engine 架构                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  输入源                                                           │
│  ┌────────────────────────────────────────────────────────────┐│
│  │  EventSources.Tracee  ← 事件流 channel                     ││
│  └────────────┬───────────────────────────────────────────────┘│
│               │                                                  │
│               ▼                                                  │
│  事件分发                                                         │
│  ┌────────────────────────────────────────────────────────────┐│
│  │  signaturesIndex: EventSelector → []Signature              ││
│  │  ┌──────────────────────────────────────────────────────┐  ││
│  │  │  {Source: "tracee", Name: "execve"}                   │  ││
│  │  │    ↓                                                  │  ││
│  │  │  [Signature1, Signature2, Signature3]                │  ││
│  │  └──────────────────────────────────────────────────────┘  ││
│  └────────────┬───────────────────────────────────────────────┘│
│               │                                                  │
│               ▼                                                  │
│  签名处理                                                         │
│  ┌────────────────────────────────────────────────────────────┐│
│  │  For each matched signature:                               ││
│  │    signature.OnEvent(event)                                ││
│  │      ↓                                                     ││
│  │    if detected:                                            ││
│  │      callback(&Finding{...})                               ││
│  └────────────┬───────────────────────────────────────────────┘│
│               │                                                  │
│               ▼                                                  │
│  输出                                                             │
│  ┌────────────────────────────────────────────────────────────┐│
│  │  output chan *detect.Finding                               ││
│  │  ↓                                                         ││
│  │  Finding {                                                 ││
│  │    SigMetadata: {Name, Severity, ...}                     ││
│  │    Data: {攻击详情}                                        ││
│  │    Event: {触发事件}                                       ││
│  │  }                                                         ││
│  └─────────────────────────────────────────────────────────────┘│
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### 5.2 Engine 核心实现 - [pkg/signatures/engine/engine.go](pkg/signatures/engine/engine.go)

```go
// Engine 签名检测引擎
type Engine struct {
    // ========== 签名管理 ==========
    signatures      map[detect.Signature]struct{}                    // 所有已加载签名
    signaturesIndex map[detect.SignatureEventSelector][]detect.Signature // 事件 → 签名索引
    signaturesMutex sync.RWMutex                                     // 保护并发访问

    // ========== 输入输出 ==========
    inputs  EventSources           // 事件输入源
    output  chan *detect.Finding   // Finding 输出 channel

    // ========== 配置和状态 ==========
    config      Config               // 引擎配置
    stats       metrics.Stats        // 统计信息
    dataSources map[string]map[string]detect.DataSource // 数据源
    dataSourcesMutex sync.RWMutex
    ctx         context.Context
}

// EventSources 输入源配置
type EventSources struct {
    Tracee chan protocol.Event // Tracee 事件 channel
}

// NewEngine 创建签名引擎
func NewEngine(
    config Config,
    sources EventSources,
    output chan *detect.Finding,
) (*Engine, error) {
    if sources.Tracee == nil || output == nil {
        return nil, errors.New("nil input received")
    }

    engine := &Engine{
        inputs:           sources,
        output:           output,
        config:           config,
        signatures:       make(map[detect.Signature]struct{}),
        signaturesIndex:  make(map[detect.SignatureEventSelector][]detect.Signature),
        dataSources:      make(map[string]map[string]detect.DataSource),
    }

    return engine, nil
}

// Init 初始化签名引擎
func (engine *Engine) Init() error {
    // ========== 注册数据源 ==========
    for _, dataSource := range engine.config.DataSources {
        err := engine.RegisterDataSource(dataSource)
        if err != nil {
            logger.Errorw("Loading data source", "error", err)
        }
    }

    // ========== 加载签名 ==========
    logger.Debugw("Loading signatures",
        "total_available", len(engine.config.AvailableSignatures),
        "selected_for_loading", len(engine.config.SelectedSignatures))

    for _, sig := range engine.config.SelectedSignatures {
        _, err := engine.loadSignature(sig)
        if err != nil {
            logger.Errorw("Failed to load signature",
                "name", sig.GetMetadata().Name,
                "error", err)
            continue
        }
    }

    return nil
}

// loadSignature 加载单个签名
func (engine *Engine) loadSignature(sig detect.Signature) (detect.Signature, error) {
    engine.signaturesMutex.Lock()
    defer engine.signaturesMutex.Unlock()

    // ========== 初始化签名 ==========
    ctx := detect.SignatureContext{
        Callback: engine.signatureCallback, // 设置回调函数
    }

    if err := sig.Init(ctx); err != nil {
        return nil, err
    }

    // ========== 获取签名元数据 ==========
    m, err := sig.GetMetadata()
    if err != nil {
        return nil, err
    }

    logger.Debugw("Loading signature",
        "name", m.Name,
        "version", m.Version)

    // ========== 注册签名 ==========
    engine.signatures[sig] = struct{}{}

    // ========== 索引签名 (按事件选择器) ==========
    selectedEvents, err := sig.GetSelectedEvents()
    if err != nil {
        return nil, err
    }

    for _, selector := range selectedEvents {
        engine.signaturesIndex[selector] = append(
            engine.signaturesIndex[selector],
            sig,
        )

        logger.Debugw("Indexed signature",
            "name", m.Name,
            "source", selector.Source,
            "event", selector.Name)
    }

    return sig, nil
}
```

### 5.3 事件处理循环

```go
// Start 启动签名引擎
func (engine *Engine) Start(ctx context.Context) {
    engine.ctx = ctx

    logger.Infow("Starting signature engine",
        "signatures_loaded", len(engine.signatures))

    // ========== 启动事件处理循环 ==========
    go func() {
        for {
            select {
            case <-ctx.Done():
                // 上下文取消，发送完成信号
                engine.sendSignalToAllSignatures(detect.SignalSourceComplete("tracee"))
                return

            case event := <-engine.inputs.Tracee:
                // ========== 处理事件 ==========
                if err := engine.OnEvent(event); err != nil {
                    logger.Warnw("Error processing event",
                        "error", err)
                }

                // 更新统计
                engine.stats.EventsProcessed.Increment()
            }
        }
    }()
}

// OnEvent 处理单个事件
func (engine *Engine) OnEvent(event protocol.Event) error {
    // ========== 提取事件信息 ==========
    traceeEvent, ok := event.Payload.(trace.Event)
    if !ok {
        return fmt.Errorf("invalid event payload type")
    }

    // ========== 构建事件选择器 ==========
    selector := detect.SignatureEventSelector{
        Source: "tracee",
        Name:   traceeEvent.EventName,
    }

    // ========== 查找匹配的签名 ==========
    engine.signaturesMutex.RLock()
    signatures := engine.signaturesIndex[selector]

    // 也查找匹配所有事件的签名
    allEventSignatures := engine.signaturesIndex[detect.SignatureEventSelector{
        Source: "tracee",
        Name:   "*",
    }]
    signatures = append(signatures, allEventSignatures...)
    engine.signaturesMutex.RUnlock()

    // ========== 将事件发送给每个匹配的签名 ==========
    for _, sig := range signatures {
        if err := sig.OnEvent(event); err != nil {
            m, _ := sig.GetMetadata()
            logger.Warnw("Signature event processing error",
                "signature", m.Name,
                "error", err)
        }
    }

    return nil
}

// signatureCallback 签名回调函数
func (engine *Engine) signatureCallback(finding *detect.Finding) {
    // ========== 发送 Finding 到输出 channel ==========
    select {
    case engine.output <- finding:
        // 更新统计
        engine.stats.FindingsEmitted.Increment()

    default:
        // Channel 满，丢弃 Finding
        logger.Warnw("Finding output channel is full, dropping finding",
            "signature", finding.SigMetadata.Name)
        engine.stats.FindingsDropped.Increment()
    }
}
```

---

## 6. 自定义签名开发

### 6.1 签名接口

```go
// Signature 定义签名接口
type Signature interface {
    // Init 初始化签名
    Init(ctx SignatureContext) error

    // GetMetadata 返回签名元数据
    GetMetadata() (SignatureMetadata, error)

    // GetSelectedEvents 返回此签名订阅的事件
    GetSelectedEvents() ([]SignatureEventSelector, error)

    // OnEvent 处理事件
    OnEvent(event protocol.Event) error

    // OnSignal 处理生命周期信号
    OnSignal(signal Signal) error
}

// SignatureContext 签名上下文
type SignatureContext struct {
    Callback SignatureHandler // Finding 回调函数
}

// SignatureHandler Finding 处理函数
type SignatureHandler func(*Finding)

// SignatureMetadata 签名元数据
type SignatureMetadata struct {
    ID          string   // 签名 ID
    Version     string   // 版本
    Name        string   // 名称
    Description string   // 描述
    Tags        []string // 标签
    Properties  map[string]interface{} // 自定义属性
}

// SignatureEventSelector 事件选择器
type SignatureEventSelector struct {
    Source string // 事件源 (如 "tracee")
    Name   string // 事件名 (如 "execve" 或 "*" 表示所有)
}

// Finding 检测结果
type Finding struct {
    SigMetadata SignatureMetadata      // 签名元数据
    Event       protocol.Event         // 触发事件
    Data        map[string]interface{} // 检测数据
}
```

### 6.2 简单签名示例

```go
// 示例1: 检测对敏感文件的访问
type SensitiveFileAccess struct {
    cb             detect.SignatureHandler
    sensitiveFiles []string
}

func (s *SensitiveFileAccess) Init(ctx detect.SignatureContext) error {
    s.cb = ctx.Callback

    // 定义敏感文件列表
    s.sensitiveFiles = []string{
        "/etc/shadow",
        "/etc/passwd",
        "/root/.ssh/id_rsa",
        "/root/.ssh/id_ecdsa",
        "/root/.ssh/id_ed25519",
    }

    return nil
}

func (s *SensitiveFileAccess) GetMetadata() (detect.SignatureMetadata, error) {
    return detect.SignatureMetadata{
        ID:          "TRC-001",
        Version:     "1.0.0",
        Name:        "Sensitive File Access",
        Description: "检测对敏感系统文件的访问",
        Tags:        []string{"security", "file-access"},
        Properties: map[string]interface{}{
            "Severity":     "HIGH",
            "MITRE ATT&CK": "T1003.008",
        },
    }, nil
}

func (s *SensitiveFileAccess) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
    return []detect.SignatureEventSelector{
        {Source: "tracee", Name: "security_file_open"},
    }, nil
}

func (s *SensitiveFileAccess) OnEvent(event protocol.Event) error {
    // ========== 提取事件 ==========
    ee, ok := event.Payload.(trace.Event)
    if !ok {
        return errors.New("invalid event payload")
    }

    // ========== 提取文件路径参数 ==========
    pathname := ""
    for _, arg := range ee.Args {
        if arg.Name == "pathname" {
            pathname = arg.Value.(string)
            break
        }
    }

    if pathname == "" {
        return nil // 没有路径参数
    }

    // ========== 检查是否为敏感文件 ==========
    for _, sensitiveFile := range s.sensitiveFiles {
        if pathname == sensitiveFile {
            // ========== 生成 Finding ==========
            m, _ := s.GetMetadata()
            s.cb(&detect.Finding{
                SigMetadata: m,
                Event:       event,
                Data: map[string]interface{}{
                    "file":     pathname,
                    "process":  ee.ProcessName,
                    "pid":      ee.ProcessID,
                    "uid":      ee.UserID,
                    "severity": "HIGH",
                    "message":  fmt.Sprintf("敏感文件 %s 被进程 %s (PID: %d) 访问",
                        pathname, ee.ProcessName, ee.ProcessID),
                },
            })
            break
        }
    }

    return nil
}

func (s *SensitiveFileAccess) OnSignal(signal detect.Signal) error {
    return nil // 不处理信号
}
```

### 6.3 高级签名示例 (状态跟踪)

```go
// 示例2: 检测反弹 Shell (多事件关联)
type ReverseShell struct {
    cb              detect.SignatureHandler
    shellProcesses  map[int32]*shellInfo // PID → shell 信息
    mu              sync.Mutex
}

type shellInfo struct {
    pid        int32
    comm       string
    timestamp  time.Time
    hasNetwork bool
}

func (s *ReverseShell) Init(ctx detect.SignatureContext) error {
    s.cb = ctx.Callback
    s.shellProcesses = make(map[int32]*shellInfo)
    return nil
}

func (s *ReverseShell) GetMetadata() (detect.SignatureMetadata, error) {
    return detect.SignatureMetadata{
        ID:          "TRC-002",
        Version:     "1.0.0",
        Name:        "Reverse Shell Detection",
        Description: "检测反弹 Shell 行为",
        Tags:        []string{"security", "network", "shell"},
        Properties: map[string]interface{}{
            "Severity":     "CRITICAL",
            "MITRE ATT&CK": "T1059",
        },
    }, nil
}

func (s *ReverseShell) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
    return []detect.SignatureEventSelector{
        {Source: "tracee", Name: "sched_process_exec"},
        {Source: "tracee", Name: "security_socket_connect"},
        {Source: "tracee", Name: "sched_process_exit"},
    }, nil
}

func (s *ReverseShell) OnEvent(event protocol.Event) error {
    ee, ok := event.Payload.(trace.Event)
    if !ok {
        return errors.New("invalid event payload")
    }

    s.mu.Lock()
    defer s.mu.Unlock()

    switch ee.EventID {
    case events.SchedProcessExec:
        // ========== 进程执行 ==========
        // 检查是否为 shell 进程
        if s.isShell(ee.ProcessName) {
            s.shellProcesses[ee.ProcessID] = &shellInfo{
                pid:        ee.ProcessID,
                comm:       ee.ProcessName,
                timestamp:  time.Unix(0, int64(ee.Timestamp)),
                hasNetwork: false,
            }
        }

    case events.SecuritySocketConnect:
        // ========== 网络连接 ==========
        // 检查是否为 shell 进程发起的连接
        if info, exists := s.shellProcesses[ee.ProcessID]; exists {
            info.hasNetwork = true

            // ========== 检测到反弹 Shell！==========
            m, _ := s.GetMetadata()
            s.cb(&detect.Finding{
                SigMetadata: m,
                Event:       event,
                Data: map[string]interface{}{
                    "process":   info.comm,
                    "pid":       info.pid,
                    "severity":  "CRITICAL",
                    "message":   fmt.Sprintf("检测到反弹 Shell: %s (PID: %d) 发起网络连接",
                        info.comm, info.pid),
                },
            })

            // 删除记录 (避免重复告警)
            delete(s.shellProcesses, ee.ProcessID)
        }

    case events.SchedProcessExit:
        // ========== 进程退出 ==========
        // 清理记录
        delete(s.shellProcesses, ee.ProcessID)
    }

    return nil
}

func (s *ReverseShell) isShell(comm string) bool {
    shells := []string{"bash", "sh", "zsh", "fish", "dash", "ksh"}
    for _, shell := range shells {
        if comm == shell {
            return true
        }
    }
    return false
}

func (s *ReverseShell) OnSignal(signal detect.Signal) error {
    // 清理过期记录
    s.mu.Lock()
    defer s.mu.Unlock()

    now := time.Now()
    for pid, info := range s.shellProcesses {
        if now.Sub(info.timestamp) > 5*time.Minute {
            delete(s.shellProcesses, pid)
        }
    }

    return nil
}
```

---

## 7. 实践练习

### 练习 1：创建自定义策略

**目标**：编写 YAML 策略监控 Docker 容器中的特权操作

```yaml
# my-container-policy.yaml
apiVersion: tracee.aquasecurity.github.io/v1beta1
kind: Policy
metadata:
  name: monitor-container-privilege
  annotations:
    description: 监控容器中的特权提升操作
spec:
  scope:
    - container=true
    - follow

  rules:
    # 监控 sudo 使用
    - event: sched_process_exec
      filters:
        - args.pathname=/usr/bin/sudo
        - args.pathname=/bin/su

    # 监控特权系统调用
    - event: cap_capable
      filters:
        - args.cap=CAP_SYS_ADMIN
        - args.cap=CAP_SYS_PTRACE

    # 监控敏感文件访问
    - event: security_file_open
      filters:
        - args.pathname=/etc/shadow
        - args.pathname=/etc/sudoers
```

测试：

```bash
# 加载策略
sudo ./dist/tracee --policy my-container-policy.yaml

# 在另一终端运行容器
docker run -it --rm ubuntu bash

# 在容器中触发事件
sudo ls
cat /etc/shadow
```

### 练习 2：实现数值范围过滤

**目标**：扩展 NumericFilter 支持范围表达式

```go
// 在 pkg/filters/numeric_filter.go 添加
func (f *NumericFilter[T]) ParseRange(expr string) error {
    // 支持格式: "100-200" 表示范围 [100, 200]

    parts := strings.Split(expr, "-")
    if len(parts) != 2 {
        return fmt.Errorf("invalid range expression: %s", expr)
    }

    min, err := strconv.ParseInt(parts[0], 10, 64)
    if err != nil {
        return err
    }

    max, err := strconv.ParseInt(parts[1], 10, 64)
    if err != nil {
        return err
    }

    // 等价于 >=min AND <=max
    f.greaterEqual[T(min)] = struct{}{}
    f.lessEqual[T(max)] = struct{}{}

    return nil
}

// 使用示例
filter := filters.NewUInt32Filter()
filter.ParseRange("1000-2000")  // 端口范围 1000-2000
filter.Enable()
```

### 练习 3：编写签名检测 SUID 提权

**目标**：检测进程使用 SUID 二进制文件

```go
// signatures/suid_execution.go
package main

import (
    "fmt"
    "os"
    "syscall"

    "github.com/aquasecurity/tracee/types/detect"
    "github.com/aquasecurity/tracee/types/protocol"
    "github.com/aquasecurity/tracee/types/trace"
)

type SUIDExecution struct {
    cb detect.SignatureHandler
}

func (s *SUIDExecution) Init(ctx detect.SignatureContext) error {
    s.cb = ctx.Callback
    return nil
}

func (s *SUIDExecution) GetMetadata() (detect.SignatureMetadata, error) {
    return detect.SignatureMetadata{
        ID:          "TRC-SUID-001",
        Version:     "1.0.0",
        Name:        "SUID Binary Execution",
        Description: "检测 SUID 二进制文件执行",
        Tags:        []string{"privilege-escalation", "suid"},
        Properties: map[string]interface{}{
            "Severity":     "MEDIUM",
            "MITRE ATT&CK": "T1548.001",
        },
    }, nil
}

func (s *SUIDExecution) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
    return []detect.SignatureEventSelector{
        {Source: "tracee", Name: "sched_process_exec"},
    }, nil
}

func (s *SUIDExecution) OnEvent(event protocol.Event) error {
    ee, ok := event.Payload.(trace.Event)
    if !ok {
        return fmt.Errorf("invalid event")
    }

    // 获取可执行文件路径
    var binaryPath string
    for _, arg := range ee.Args {
        if arg.Name == "pathname" {
            binaryPath = arg.Value.(string)
            break
        }
    }

    if binaryPath == "" {
        return nil
    }

    // 检查文件是否设置了 SUID 位
    fileInfo, err := os.Stat(binaryPath)
    if err != nil {
        return nil // 文件不存在或无法访问
    }

    stat := fileInfo.Sys().(*syscall.Stat_t)
    mode := stat.Mode

    // 检查 SUID 位 (S_ISUID = 04000)
    if mode&syscall.S_ISUID != 0 {
        // 检测到 SUID 执行
        m, _ := s.GetMetadata()
        s.cb(&detect.Finding{
            SigMetadata: m,
            Event:       event,
            Data: map[string]interface{}{
                "binary":   binaryPath,
                "process":  ee.ProcessName,
                "pid":      ee.ProcessID,
                "uid":      ee.UserID,
                "euid":     stat.Uid, // 有效 UID
                "severity": "MEDIUM",
                "message":  fmt.Sprintf("检测到 SUID 二进制执行: %s", binaryPath),
            },
        })
    }

    return nil
}

func (s *SUIDExecution) OnSignal(signal detect.Signal) error {
    return nil
}
```

### 练习 4：策略性能测试

**目标**：测量策略匹配的性能

```go
// pkg/policy/policy_manager_bench_test.go
package policy

import (
    "testing"

    "github.com/aquasecurity/tracee/pkg/events"
    "github.com/aquasecurity/tracee/types/trace"
)

func BenchmarkPolicyMatch(b *testing.B) {
    // 创建策略管理器
    manager, _ := NewManager(ManagerConfig{}, depsManager, createTestPolicies()...)

    // 创建测试事件
    event := &trace.Event{
        EventID:     events.SecurityFileOpen,
        ProcessID:   1234,
        ProcessName: "bash",
        UserID:      0,
        Container: trace.Container{
            ID: "abc123",
        },
        Args: []trace.Argument{
            {Name: "pathname", Value: "/etc/shadow"},
        },
    }

    b.ResetTimer()

    for i := 0; i < b.N; i++ {
        manager.MatchPolicy(event)
    }
}

func createTestPolicies() []*Policy {
    // 创建多个测试策略
    policies := make([]*Policy, 10)

    for i := 0; i < 10; i++ {
        p := NewPolicy()
        p.ID = i
        p.Name = fmt.Sprintf("policy-%d", i)

        // 添加规则
        p.Rules[events.SecurityFileOpen] = RuleData{
            EventID: events.SecurityFileOpen,
        }

        policies[i] = p
    }

    return policies
}

// 运行基准测试
// go test -bench=BenchmarkPolicyMatch -benchmem ./pkg/policy
```

---

## 8. 总结与下一步

### 本阶段掌握的内容

- ✅ 策略系统的完整架构
- ✅ Policy 结构和过滤器设计
- ✅ 策略管理器的实现原理
- ✅ 签名检测引擎的工作流程
- ✅ 自定义签名的开发方法

### 关键设计模式

| 模式 | 应用 | 优势 |
|------|------|------|
| **策略模式** | 过滤器系统 | 可扩展、可组合 |
| **观察者模式** | 签名引擎 | 事件驱动、解耦 |
| **索引模式** | 签名分发 | 快速查找 |
| **位图模式** | 策略匹配 | 高效存储 |
| **回调模式** | Finding 生成 | 异步处理 |

### 策略系统最佳实践

1. **分层过滤**：eBPF 侧做粗过滤，用户空间做精细过滤
2. **早期过滤**：尽早过滤不匹配的事件，减少后续开销
3. **状态管理**：签名中维护最小必要状态
4. **性能优化**：使用索引、缓存、对象池
5. **错误处理**：签名错误不应影响其他签名

### 下一步学习

继续第六阶段：**[容器感知与集成](06-container-integration.md)**

重点内容：
- CGroup 深度解析
- 容器运行时适配细节
- Kubernetes API 集成
- 容器网络追踪
- 性能调优技巧

---

**上一篇**：[第四阶段：用户空间实现](04-userspace-implementation.md) | **下一篇**：[第六阶段：容器集成](06-container-integration.md)
