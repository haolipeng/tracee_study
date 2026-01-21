# Tracee 事件过滤机制深度解析

**预估学习时长：2-3天**
**难度等级：中高级**

---

## 目录

1. [概述与学习目标](#概述与学习目标)
2. [过滤机制架构概览](#过滤机制架构概览)
3. [内核态过滤 (eBPF层)](#内核态过滤-ebpf层)
4. [用户态过滤](#用户态过滤)
5. [Policy 到过滤规则的转换](#policy-到过滤规则的转换)
6. [过滤表达式语法](#过滤表达式语法)
7. [Scope 过滤 vs Event 过滤](#scope-过滤-vs-event-过滤)
8. [过滤优化策略](#过滤优化策略)
9. [动手练习](#动手练习)
10. [核心代码走读](#核心代码走读)

---

## 概述与学习目标

### 什么是事件过滤

Tracee 作为一个基于 eBPF 的运行时安全和取证工具，能够监控系统中发生的大量事件。然而，并非所有事件都是用户关心的。事件过滤机制允许用户：

- **精确控制**：只追踪感兴趣的事件
- **降低开销**：减少不必要的事件处理
- **提升性能**：在内核态尽早丢弃无关事件

### 学习目标

完成本教程后，你将能够：

1. 理解 Tracee 双层过滤架构（内核态 + 用户态）
2. 掌握 eBPF Maps 在过滤中的作用
3. 理解 Policy 如何转换为过滤规则
4. 编写复杂的过滤表达式
5. 区分 Scope 过滤和 Event 过滤的使用场景
6. 理解过滤性能优化策略

### 核心源码文件

| 目录/文件 | 描述 |
|-----------|------|
| `pkg/filters/` | 用户态过滤器实现 |
| `pkg/ebpf/c/common/filtering.h` | 内核态过滤逻辑 |
| `pkg/ebpf/c/maps.h` | eBPF Maps 定义 |
| `pkg/ebpf/c/types.h` | 核心数据结构 |
| `pkg/policy/` | Policy 管理和转换 |

---

## 过滤机制架构概览

### 双层过滤架构

Tracee 采用**内核态 + 用户态**双层过滤架构：

```
┌─────────────────────────────────────────────────────────────┐
│                      用户空间 (User Space)                   │
├─────────────────────────────────────────────────────────────┤
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐  │
│  │   Policy     │───>│   Filters    │───>│   Output     │  │
│  │   Engine     │    │  (Userland)  │    │   Engine     │  │
│  └──────────────┘    └──────────────┘    └──────────────┘  │
│         │                   ▲                              │
│         │ 配置过滤规则       │ 用户态过滤                    │
│         ▼                   │                              │
├─────────────────────────────────────────────────────────────┤
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐  │
│  │  BPF Maps    │◄───│  eBPF Progs  │◄───│  Syscalls/   │  │
│  │  (Filters)   │    │  (Filtering) │    │  Kprobes     │  │
│  └──────────────┘    └──────────────┘    └──────────────┘  │
│                      内核空间 (Kernel Space)                 │
└─────────────────────────────────────────────────────────────┘
```

### 过滤时机

1. **内核态过滤（早期过滤）**
   - 在事件生成时立即过滤
   - 过滤条件存储在 eBPF Maps 中
   - 避免不必要的数据传输到用户态

2. **用户态过滤（精细过滤）**
   - 处理内核态无法完成的复杂过滤
   - 支持更丰富的过滤表达式
   - 处理容器元数据等动态信息

### 过滤类型总览

```
┌─────────────────────────────────────────────────────────────┐
│                        过滤类型                              │
├─────────────────────────┬───────────────────────────────────┤
│   Scope 过滤 (范围)      │   Event 过滤 (事件)              │
├─────────────────────────┼───────────────────────────────────┤
│ • UID/PID               │ • Event Data (参数)              │
│ • Process Name (comm)   │ • Return Value                   │
│ • Mount Namespace       │ • Event-specific Scope           │
│ • PID Namespace         │                                  │
│ • Container             │                                  │
│ • Binary Path           │                                  │
│ • Process Tree          │                                  │
│ • UTS Namespace         │                                  │
│ • Cgroup ID             │                                  │
└─────────────────────────┴───────────────────────────────────┘
```

---

## 内核态过滤 (eBPF层)

### 过滤发生的时机

内核态过滤在 eBPF 程序中执行，发生在事件被提交到 perf buffer 之前。核心过滤函数位于 `pkg/ebpf/c/common/filtering.h`：

```c
// 主要过滤函数
statfunc bool evaluate_scope_filters(program_data_t *p)
{
    u64 matched_policies = match_scope_filters(p);
    p->event->context.matched_policies &= matched_policies;
    return p->event->context.matched_policies != 0;
}

statfunc bool evaluate_data_filters(program_data_t *p, u8 index)
{
    u64 matched_data_filters = match_data_filters(p, index);
    p->event->context.matched_policies &= matched_data_filters;
    return p->event->context.matched_policies != 0;
}
```

### 过滤流程

```
┌──────────────────────────────────────────────────────────────┐
│                    eBPF 程序执行流程                          │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  1. 事件触发 (syscall/kprobe/tracepoint)                     │
│         │                                                    │
│         ▼                                                    │
│  2. 检查事件是否被选中 (event_is_selected)                    │
│         │                                                    │
│         ▼                                                    │
│  3. 执行 Scope 过滤 (match_scope_filters)                    │
│     ├── 布尔过滤器 (container, new_container, new_pid)        │
│     ├── 数值过滤器 (uid, pid, mnt_ns, pid_ns, cgroup_id)     │
│     ├── 字符串过滤器 (comm, uts_name)                        │
│     ├── 二进制过滤器 (binary path)                           │
│     └── 进程树过滤器 (process tree)                          │
│         │                                                    │
│         ▼                                                    │
│  4. 执行 Data 过滤 (match_data_filters)                      │
│     ├── 精确匹配 (exact match)                               │
│     ├── 前缀匹配 (prefix match via LPM Trie)                 │
│     └── 后缀匹配 (suffix match via LPM Trie)                 │
│         │                                                    │
│         ▼                                                    │
│  5. 检查 matched_policies != 0                               │
│         │                                                    │
│    ┌────┴────┐                                               │
│    ▼         ▼                                               │
│  提交事件   丢弃事件                                          │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

### 过滤条件的传递

用户态通过 eBPF Maps 将过滤条件传递给内核态。核心 Maps 定义在 `pkg/ebpf/c/maps.h`：

#### 1. 版本化的过滤 Maps（Map of Maps）

```c
// UID 过滤 Map
struct uid_filter {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, u32);           // UID 值
    __type(value, eq_t);        // 等式结构
} uid_filter SEC(".maps");

// UID 过滤版本 Map（外层 Map）
struct uid_filter_version {
    __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
    __uint(max_entries, MAX_FILTER_VERSION);  // 64
    __type(key, u16);                          // 版本号
    __array(values, uid_filter_t);             // 内层 Map
} uid_filter_version SEC(".maps");
```

#### 2. 等式结构 (eq_t)

```c
typedef struct equality {
    // 位图：哪些策略使用 '=' 操作符（0 表示 '!='）
    u64 equals_in_policies;
    // 位图：哪些策略使用了该 key
    u64 key_used_in_policies;
} eq_t;
```

这个结构是过滤逻辑的核心。通过位图操作，可以同时处理多达 64 个策略的过滤条件。

#### 3. 策略配置结构

```c
typedef struct policies_config {
    // 位图：哪些策略启用了该过滤器
    u64 uid_filter_enabled;
    u64 pid_filter_enabled;
    u64 mnt_ns_filter_enabled;
    // ... 其他过滤器

    // 位图：key 不存在时是否匹配
    u64 uid_filter_match_if_key_missing;
    u64 pid_filter_match_if_key_missing;
    // ... 其他

    // 启用的策略位图
    u64 enabled_policies;

    // 全局范围过滤
    u64 uid_max;
    u64 uid_min;
    u64 pid_max;
    u64 pid_min;
} policies_config_t;
```

### 核心过滤函数分析

#### match_scope_filters

这是 Scope 过滤的核心函数：

```c
statfunc u64 match_scope_filters(program_data_t *p)
{
    task_context_t *context = &p->event->context.task;

    // 不监控 Tracee 自身
    if (p->config->tracee_pid == context->host_pid)
        return 0;

    proc_info_t *proc_info = p->proc_info;
    policies_config_t *policies_cfg = &p->event->policies_config;
    u64 res = ~0ULL;  // 初始化为全 1

    //
    // 布尔过滤器（不使用版本化的 Map）
    //
    if (policies_cfg->cont_filter_enabled) {
        bool is_container = false;
        u8 state = p->task_info->container_state;
        if (state == CONTAINER_STARTED || state == CONTAINER_EXISTED)
            is_container = true;
        u64 match_bitmap = policies_cfg->cont_filter_match_if_key_missing;
        u64 mask = ~policies_cfg->cont_filter_enabled;

        res &= bool_filter_matches(match_bitmap, is_container) | mask;
    }

    //
    // 等式过滤器（使用版本化的 Map）
    //
    u16 version = p->event->context.policies_version;
    void *filter_map = NULL;

    if (policies_cfg->uid_filter_enabled) {
        context->uid = bpf_get_current_uid_gid();
        u64 match_if_key_missing = policies_cfg->uid_filter_match_if_key_missing;
        u64 mask = ~policies_cfg->uid_filter_enabled;
        u64 max = policies_cfg->uid_max;
        u64 min = policies_cfg->uid_min;

        filter_map = get_filter_map(&uid_filter_version, version);
        res &= uint_filter_range_matches(
                   match_if_key_missing, filter_map, context->uid, max, min) |
               mask;
    }

    // ... 其他过滤器

    // 确保只返回启用的策略
    return res & policies_cfg->enabled_policies;
}
```

#### equality_filter_matches

这是等式过滤的核心逻辑：

```c
statfunc u64 equality_filter_matches(u64 match_if_key_missing, void *filter_map, void *key)
{
    // 示例：
    //   policy 2: comm=who
    //   policy 3: comm=ping
    //   policy 4: comm!=who
    //
    // match_if_key_missing = 0000 1000 (policy 4 使用 "!=")
    //
    // 对于 "who" 命令的事件：
    //   equals_in_policies   = 0000 0010 (policy 2 使用 "=")
    //   key_used_in_policies = 0000 1010 (policy 2 和 4 使用 "who")
    //
    //   return = equals_in_policies | (match_if_key_missing & ~key_used_in_policies)
    //          = 0000 0010 | (0000 1000 & 1111 0101)
    //          = 0000 0010 | 0000 0000
    //          = 0000 0010  (只有 policy 2 匹配)

    u64 equals_in_policies = 0;
    u64 key_used_in_policies = 0;

    if (filter_map) {
        eq_t *equality = bpf_map_lookup_elem(filter_map, key);
        if (equality != NULL) {
            equals_in_policies = equality->equals_in_policies;
            key_used_in_policies = equality->key_used_in_policies;
        }
    }

    // 匹配条件：
    // 1. key 被使用且等式匹配 (equals_in_policies)
    // 2. key 未被使用且默认动作是匹配 (match_if_key_missing)
    return equals_in_policies | (match_if_key_missing & ~key_used_in_policies);
}
```

### 数据过滤 (Data Filter)

Data 过滤支持对事件参数进行过滤，使用 LPM Trie 实现前缀/后缀匹配：

```c
statfunc u64 match_data_filters(program_data_t *p, u8 index)
{
    policies_config_t *policies_cfg = &p->event->policies_config;
    string_filter_config_t *str_filter = &p->event->config.data_filter.string;

    // 检查是否启用了任何字符串过滤
    if (!(str_filter->exact_enabled ||
          str_filter->prefix_enabled ||
          str_filter->suffix_enabled))
        return policies_cfg->enabled_policies;

    u64 res = 0;
    u32 eventid = p->event->context.eventid;
    u16 version = p->event->context.policies_version;

    // 精确匹配
    if (str_filter->exact_enabled) {
        // 从参数缓冲区加载字符串
        // 查询 data_filter_exact_version Map
        // 计算匹配结果
    }

    // 前缀匹配（使用 LPM Trie）
    if (str_filter->prefix_enabled) {
        // 使用 LPM Trie 进行前缀匹配
    }

    // 后缀匹配（字符串反转后使用 LPM Trie）
    if (str_filter->suffix_enabled) {
        // 字符串反转后进行 LPM Trie 匹配
    }

    return res & policies_cfg->enabled_policies;
}
```

### 性能优势

1. **早期丢弃**：不匹配的事件在内核态直接丢弃，不传输到用户态
2. **位图操作**：使用 64 位位图，单次操作可处理 64 个策略
3. **Map 查找**：O(1) 的哈希查找或 O(log n) 的 LPM Trie 查找
4. **版本化 Maps**：支持热更新过滤规则，无需重新加载 eBPF 程序

---

## 用户态过滤

### Filter 类型详解

用户态过滤器定义在 `pkg/filters/` 目录下：

#### 1. Filter 接口

```go
// pkg/filters/filters.go
type Filter[T any] interface {
    Clone() T
    Filter(val interface{}) bool  // 执行过滤
    Parse(operatorAndValues string) error  // 解析过滤表达式
    Enable()
    Disable()
    Enabled() bool
}
```

#### 2. NumericFilter - 数值过滤器

支持数值比较操作：

```go
// pkg/filters/numeric.go
type NumericFilter[T NumericConstraint] struct {
    equal    map[T]struct{}    // 等于
    notEqual map[T]struct{}    // 不等于
    min      T                 // 最小值
    max      T                 // 最大值
    enabled  bool
}

// 过滤优先级：equality > greater > lesser > non-equality
func (f *NumericFilter[T]) filter(val T) bool {
    _, inEqual := f.equal[val]
    _, inNotEqual := f.notEqual[val]

    if !f.enabled {
        return true
    }

    // 1. 检查等于
    if inEqual {
        return true
    }

    // 2. 检查不等于
    if inNotEqual {
        return false
    }

    // 3. 检查范围
    if f.min != f.unsetMin || f.max != f.unsetMax {
        return f.InMinMaxRange(val)
    }

    return false
}
```

#### 3. StringFilter - 字符串过滤器

支持精确匹配、前缀、后缀和包含：

```go
// pkg/filters/string.go
type StringFilter struct {
    equal       map[string]struct{}  // 精确相等
    notEqual    map[string]struct{}  // 精确不等
    prefixes    sets.PrefixSet       // 前缀匹配
    suffixes    sets.SuffixSet       // 后缀匹配
    contains    map[string]struct{}  // 包含匹配
    notPrefixes sets.PrefixSet       // 前缀不匹配
    notSuffixes sets.SuffixSet       // 后缀不匹配
    notContains map[string]struct{}  // 不包含匹配
    enabled     bool
}

// 过滤优先级：
// 1. equality, suffixed, prefixed, contains
// 2. not equals, not suffixed, not prefixed, not contains
func (f *StringFilter) filter(val string) bool {
    // 正向匹配
    if f.equal[val] {
        return true
    }
    if f.suffixes.Filter(val) || f.prefixes.Filter(val) {
        return true
    }
    for contain := range f.contains {
        if strings.Contains(val, contain) {
            return true
        }
    }

    // 反向匹配
    if len(f.notEqual) > 0 || ... {
        if f.notSuffixes.Filter(val) || f.notPrefixes.Filter(val) {
            return false
        }
        // ...
    }

    return false
}
```

#### 4. BoolFilter - 布尔过滤器

```go
// pkg/filters/bool.go
type BoolFilter struct {
    trueEnabled  bool
    falseEnabled bool
    enabled      bool
}

// 支持的表达式：
// field -> field=true
// not-field -> field=false
// field=true
// field=false
// field!=true
// field!=false
```

#### 5. BinaryFilter - 二进制路径过滤器

```go
// pkg/filters/binary.go
type NSBinary struct {
    MntNS uint32  // Mount Namespace
    Path  string  // 二进制路径
}

type BinaryFilter struct {
    equal    map[NSBinary]struct{}
    notEqual map[NSBinary]struct{}
    enabled  bool
}

// 支持的格式：
// /path/to/binary                    - 任意 namespace
// host:/path/to/binary               - 主机 namespace
// 4026531840:/path/to/binary         - 指定 namespace ID
```

#### 6. ProcessTreeFilter - 进程树过滤器

```go
// pkg/filters/processtree.go
type ProcessTreeFilter struct {
    equal    map[uint32]struct{}  // 追踪的 PID 及其后代
    notEqual map[uint32]struct{}  // 不追踪的 PID 及其后代
    enabled  bool
}
```

### ScopeFilter - 作用域过滤器

ScopeFilter 组合了多种过滤器，用于事件级别的 Scope 过滤：

```go
// pkg/filters/scope.go
type ScopeFilter struct {
    enabled                    bool
    timestampFilter            *NumericFilter[int64]
    processorIDFilter          *NumericFilter[int64]
    pidFilter                  *NumericFilter[int64]
    tidFilter                  *NumericFilter[int64]
    ppidFilter                 *NumericFilter[int64]
    hostPidFilter              *NumericFilter[int64]
    hostTidFilter              *NumericFilter[int64]
    hostPpidFilter             *NumericFilter[int64]
    uidFilter                  *NumericFilter[int64]
    mntNSFilter                *NumericFilter[int64]
    pidNSFilter                *NumericFilter[int64]
    processNameFilter          *StringFilter
    hostNameFilter             *StringFilter
    cgroupIDFilter             *NumericFilter[uint64]
    containerFilter            *BoolFilter
    containerIDFilter          *StringFilter
    containerImageFilter       *StringFilter
    containerImageDigestFilter *StringFilter
    containerNameFilter        *StringFilter
    podNameFilter              *StringFilter
    podNSFilter                *StringFilter
    podUIDFilter               *StringFilter
    podSandboxFilter           *BoolFilter
    syscallFilter              *StringFilter
}

// 执行过滤
func (f *ScopeFilter) Filter(evt trace.Event) bool {
    if !f.enabled {
        return true
    }

    // 所有过滤器必须都通过
    return f.containerFilter.Filter(evt.Container.ID != "") &&
        f.processNameFilter.Filter(evt.ProcessName) &&
        f.timestampFilter.Filter(int64(evt.Timestamp)) &&
        // ... 其他过滤器
}
```

### DataFilter - 数据过滤器

用于过滤事件参数：

```go
// pkg/filters/data.go
type DataFilter struct {
    filters          map[string]Filter[*StringFilter]  // fieldName -> filter
    kernelDataFilter *KernelDataFilter                 // 内核过滤器状态
    enabled          bool
}

// 过滤事件参数
func (f *DataFilter) Filter(data []trace.Argument) bool {
    if !f.Enabled() {
        return true
    }

    for fieldName, filter := range f.filters {
        // 如果该字段已在内核过滤，跳过用户态过滤
        if f.kernelDataFilter.IsKernelFilterEnabled(fieldName) {
            continue
        }

        // 在事件参数中查找该字段
        found := false
        var fieldVal interface{}
        for _, field := range data {
            if field.Name == fieldName {
                found = true
                fieldVal = field.Value
                break
            }
        }

        if !found {
            return false
        }

        if !filter.Filter(fieldVal) {
            return false
        }
    }

    return true
}
```

---

## Policy 到过滤规则的转换

### Policy 结构

```go
// pkg/policy/policy.go
type Policy struct {
    ID                int
    Name              string
    UIDFilter         *filters.NumericFilter[uint32]
    PIDFilter         *filters.NumericFilter[uint32]
    NewPidFilter      *filters.BoolFilter
    MntNSFilter       *filters.NumericFilter[uint64]
    PidNSFilter       *filters.NumericFilter[uint64]
    UTSFilter         *filters.StringFilter
    CommFilter        *filters.StringFilter
    ContFilter        *filters.BoolFilter
    NewContFilter     *filters.BoolFilter
    ContIDFilter      *filters.StringFilter
    ProcessTreeFilter *filters.ProcessTreeFilter
    BinaryFilter      *filters.BinaryFilter
    Follow            bool
    Rules             map[events.ID]RuleData
}

type RuleData struct {
    EventID     events.ID
    ScopeFilter *filters.ScopeFilter  // 事件级别 Scope
    DataFilter  *filters.DataFilter   // 数据过滤
    RetFilter   *filters.NumericFilter[int64]  // 返回值过滤
}
```

### 等式计算

Policy 中的过滤器需要转换为 eBPF Map 中的等式结构：

```go
// pkg/policy/equality.go
type equality struct {
    equalsInPolicies  uint64  // 哪些策略使用 "="
    keyUsedInPolicies uint64  // 哪些策略使用该 key
}

// 更新等式
func equalUpdate(eq *equality, policyID uint) {
    // Equal == 1, 设置位图位
    bitwise.SetBit(&eq.equalsInPolicies, policyID)
    bitwise.SetBit(&eq.keyUsedInPolicies, policyID)
}

func notEqualUpdate(eq *equality, policyID uint) {
    // NotEqual == 0, 清除位图位
    bitwise.ClearBit(&eq.equalsInPolicies, policyID)
    bitwise.SetBit(&eq.keyUsedInPolicies, policyID)
}
```

### 转换流程

```
┌─────────────────────────────────────────────────────────────┐
│                    Policy 到 eBPF Map 转换                   │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  1. 解析 Policy 文件 (YAML)                                  │
│         │                                                    │
│         ▼                                                    │
│  2. 创建 Policy 对象，填充各类 Filter                        │
│         │                                                    │
│         ▼                                                    │
│  3. computeFilterEqualities() - 计算过滤等式                 │
│     │                                                        │
│     ├── UID 等式: map[uint32]equality                       │
│     ├── PID 等式: map[uint32]equality                       │
│     ├── Comm 等式: map[string]equality                      │
│     ├── Binary 等式: map[NSBinary]equality                  │
│     └── ... 其他                                             │
│         │                                                    │
│         ▼                                                    │
│  4. 创建/更新 eBPF Maps                                      │
│     │                                                        │
│     ├── createNewFilterMapsVersion() - 创建版本化内层 Map    │
│     ├── updateOuterMap() - 更新外层 Map                     │
│     └── updateUIntFilterBPF() - 填充过滤值                  │
│         │                                                    │
│         ▼                                                    │
│  5. 更新 policies_config Map                                 │
│     │                                                        │
│     └── computePoliciesConfig() - 计算配置位图               │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### 更新 BPF Maps

```go
// pkg/policy/ebpf.go
func (ps *policies) updateBPF(
    bpfModule *bpf.Module,
    cts *containers.Manager,
    rules map[events.ID]*eventFlags,
    eventsFields map[events.ID][]data.DecodeAs,
    createNewMaps bool,
    updateProcTree bool,
) (*PoliciesConfig, error) {
    // 1. 计算过滤等式
    fEqs := &filtersEqualities{...}
    ps.computeFilterEqualities(fEqs, cts)
    ps.computeDataFilterEqualities(fEqs, fEvtCfg)

    // 2. 创建新的 Map 版本
    if createNewMaps {
        ps.createNewEventsMapVersion(bpfModule, rules, eventsFields, fEvtCfg)
        ps.createNewFilterMapsVersion(bpfModule)
        ps.createNewDataFilterMapsVersion(bpfModule, fEqs)
    }

    // 3. 更新过滤 Maps
    updateUIntFilterBPF(ps, fEqs.uidEqualities, UIDFilterMap)
    updateUIntFilterBPF(ps, fEqs.pidEqualities, PIDFilterMap)
    ps.updateStringFilterBPF(fEqs.commEqualities, CommFilterMap)
    ps.updateBinaryFilterBPF(fEqs.binaryEqualities, BinaryFilterMap)
    // ...

    // 4. 更新策略配置
    pCfg := ps.computePoliciesConfig()
    pCfg.UpdateBPF(ps.bpfInnerMaps[PoliciesConfigMap])

    return pCfg, nil
}
```

---

## 过滤表达式语法

### 基本语法

```
<field><operator><value>[,<value>...]
```

### 操作符

| 操作符 | 描述 | 适用类型 |
|--------|------|----------|
| `=` | 等于 | 所有类型 |
| `!=` | 不等于 | 所有类型 |
| `>` | 大于 | 数值 |
| `<` | 小于 | 数值 |
| `>=` | 大于等于 | 数值 |
| `<=` | 小于等于 | 数值 |

### 字符串通配符

| 模式 | 描述 | 示例 |
|------|------|------|
| `value` | 精确匹配 | `comm=bash` |
| `value*` | 前缀匹配 | `comm=bash*` |
| `*value` | 后缀匹配 | `comm=*sh` |
| `*value*` | 包含匹配 | `comm=*bash*` |

### Scope 过滤表达式示例

```yaml
# Policy 文件中的 scope 定义
scope:
  - uid=1000               # UID 等于 1000
  - pid!=1                 # PID 不等于 1
  - comm=bash,sh,zsh       # 进程名是 bash、sh 或 zsh
  - container              # 只在容器内
  - not-container          # 只在容器外
  - tree=1234              # PID 1234 的进程树
  - binary=/usr/bin/curl   # 二进制路径
  - binary=host:/usr/bin/* # 主机 namespace 下的前缀匹配
  - follow                 # 追踪子进程
```

### Event 过滤表达式示例

```yaml
rules:
  - event: security_file_open
    filters:
      - data.pathname=/etc/passwd          # 精确匹配
      - data.pathname=/etc/*               # 前缀匹配
      - data.pathname=*.so                 # 后缀匹配
      - retval=0                           # 返回值等于 0
```

### Policy 文件完整示例

```yaml
apiVersion: tracee.aquasec.com/v1beta1
kind: Policy
metadata:
  name: sensitive-file-access
  annotations:
    description: Monitor sensitive file access
spec:
  scope:
    - container                          # 只在容器内
    - not-comm=tracee                    # 排除 tracee 自身
  defaultActions:
    - log
  rules:
    - event: security_file_open
      filters:
        - data.pathname=/etc/passwd
        - data.pathname=/etc/shadow
        - data.pathname=/etc/sudoers*
    - event: security_file_open
      filters:
        - data.pathname=/root/.ssh/*
```

---

## Scope 过滤 vs Event 过滤

### 概念区分

```
┌─────────────────────────────────────────────────────────────┐
│                        Policy                               │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ Scope 过滤（全局）                                   │   │
│  │ - 应用于所有事件                                     │   │
│  │ - 定义 "谁" 被监控                                   │   │
│  │ - uid, pid, comm, container, binary, tree...        │   │
│  └─────────────────────────────────────────────────────┘   │
│                          │                                  │
│                          ▼                                  │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ Event 过滤（事件级别）                               │   │
│  │ - 应用于特定事件                                     │   │
│  │ - 定义 "什么" 事件被关注                             │   │
│  │ - data.*, retval, event-specific scope              │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 过滤位置

| 类型 | 内核态 | 用户态 | 说明 |
|------|--------|--------|------|
| **Scope 过滤** | | | |
| uid/pid | 是 | 可选 | 范围过滤可能在用户态 |
| comm | 是 | 否 | |
| container | 是 | 否 | |
| binary | 是 | 否 | |
| tree | 是 | 否 | |
| mntns/pidns | 是 | 否 | |
| **Event 过滤** | | | |
| data (pathname) | 是 | 是 | 内核态过滤特定事件 |
| retval | 否 | 是 | 仅用户态 |
| containerID | 否 | 是 | 需要容器运行时信息 |
| containerImage | 否 | 是 | 需要容器运行时信息 |
| podName/podNS | 否 | 是 | 需要 K8s 信息 |

### 使用建议

1. **优先使用 Scope 过滤**
   - 尽可能缩小监控范围
   - 在内核态过滤，性能最佳

2. **Event 过滤用于精细控制**
   - 针对特定事件的参数过滤
   - 处理复杂的业务逻辑

3. **组合使用**
   ```yaml
   scope:
     - container              # Scope: 只在容器内
     - comm!=tracee           # Scope: 排除 tracee
   rules:
     - event: security_file_open
       filters:
         - data.pathname=/etc/*  # Event: 只关注 /etc 目录
   ```

---

## 过滤优化策略

### 1. 内核态过滤优先

越早过滤，性能越好：

```
性能排序（从好到差）：
1. 事件选择（不关注的事件根本不触发）
2. 内核态 Scope 过滤
3. 内核态 Data 过滤
4. 用户态过滤
```

### 2. 版本化更新

Tracee 使用 Map of Maps 实现过滤规则的热更新：

```go
// 外层 Map 按版本号索引内层 Map
struct uid_filter_version {
    __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
    __type(key, u16);           // 版本号
    __array(values, uid_filter_t);
};
```

优势：
- 原子切换过滤规则
- 无需重新加载 eBPF 程序
- 平滑过渡，不丢失事件

### 3. 位图操作

使用 64 位位图同时处理多个策略：

```c
// 单次操作处理 64 个策略
res &= equality_filter_matches(match_if_key_missing, filter_map, key) | mask;
```

### 4. LPM Trie 用于前缀/后缀匹配

```c
// 使用 LPM Trie 实现 O(log n) 的前缀匹配
struct data_filter_prefix {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, data_filter_lpm_key_t);
    __type(value, eq_t);
};
```

### 5. 全局范围优化

当所有策略都使用相同的范围过滤时，可以使用全局 min/max：

```go
// pkg/policy/policies_compute.go
func (ps *policies) calculateGlobalMinMax() {
    // 如果所有策略的 UID 过滤都有 min/max
    // 则计算全局 min/max，在内核态快速过滤
    if !ps.uidFilterableInUserland {
        for _, p := range ps.allFromMap() {
            if p.UIDFilter.Minimum() < ps.uidFilterMin {
                ps.uidFilterMin = p.UIDFilter.Minimum()
            }
            // ...
        }
    }
}
```

### 6. 用户态策略优化

只有需要用户态过滤的策略才放入用户态过滤列表：

```go
func (ps *policies) updateUserlandPolicies() {
    for _, p := range ps.allFromArray() {
        hasUserlandFilters := false

        for _, rule := range p.Rules {
            if rule.DataFilter.Enabled() ||
                rule.RetFilter.Enabled() ||
                rule.ScopeFilter.Enabled() {
                hasUserlandFilters = true
                break
            }
        }

        if hasUserlandFilters {
            userlandList = append(userlandList, p)
        }
    }
}
```

---

## 动手练习

### 练习 1：理解位图过滤

**目标**：理解 equality 结构如何支持多策略过滤

**场景**：
- Policy 0: `comm=bash`
- Policy 1: `comm=sh`
- Policy 2: `comm!=bash`

**问题**：
1. 计算 "bash" 在 comm_filter Map 中的 equality 值
2. 计算 "sh" 在 comm_filter Map 中的 equality 值
3. 当进程名为 "bash" 时，哪些策略匹配？
4. 当进程名为 "zsh" 时，哪些策略匹配？

<details>
<summary>答案</summary>

1. "bash" 的 equality：
   - `equals_in_policies = 0b001` (Policy 0 使用 =)
   - `key_used_in_policies = 0b101` (Policy 0, 2 使用 bash)

2. "sh" 的 equality：
   - `equals_in_policies = 0b010` (Policy 1 使用 =)
   - `key_used_in_policies = 0b010` (Policy 1 使用 sh)

3. 进程名 "bash"：
   - 查找 "bash"：`equals_in_policies = 0b001`
   - `match_if_key_missing = 0b100` (Policy 2 使用 !=)
   - `result = 0b001 | (0b100 & ~0b101) = 0b001 | 0b000 = 0b001`
   - **Policy 0 匹配**

4. 进程名 "zsh"：
   - 查找 "zsh"：未找到，`equals_in_policies = 0, key_used_in_policies = 0`
   - `result = 0 | (0b100 & ~0b000) = 0b100`
   - **Policy 2 匹配**
</details>

### 练习 2：编写 Policy

**目标**：编写一个 Policy 文件来监控敏感操作

**需求**：
1. 只在容器内监控
2. 排除进程名为 "containerd" 和 "runc"
3. 监控以下事件：
   - `security_file_open`：pathname 为 `/etc/shadow` 或以 `/root/` 开头
   - `execve`：返回值为 0

<details>
<summary>答案</summary>

```yaml
apiVersion: tracee.aquasec.com/v1beta1
kind: Policy
metadata:
  name: container-sensitive-ops
  annotations:
    description: Monitor sensitive operations in containers
spec:
  scope:
    - container
    - comm!=containerd,runc
  defaultActions:
    - log
  rules:
    - event: security_file_open
      filters:
        - data.pathname=/etc/shadow
    - event: security_file_open
      filters:
        - data.pathname=/root/*
    - event: execve
      filters:
        - retval=0
```
</details>

### 练习 3：追踪过滤流程

**目标**：使用调试工具追踪过滤流程

**步骤**：

1. 启动 Tracee 并启用详细日志：
   ```bash
   sudo ./dist/tracee --log debug --filter comm=bash
   ```

2. 在另一个终端运行：
   ```bash
   bash -c "echo hello"
   ```

3. 观察日志，找出：
   - 哪些事件被过滤？
   - 过滤发生在内核态还是用户态？

### 练习 4：实现自定义过滤器

**目标**：在 `pkg/filters/` 中实现一个新的过滤器

**需求**：实现一个 `PortRangeFilter`，支持以下语法：
- `port=80,443` - 匹配指定端口
- `port=1000-2000` - 匹配端口范围
- `port!=22` - 排除端口

**提示**：
1. 参考 `NumericFilter` 的实现
2. 添加范围解析逻辑
3. 实现 `Filter` 接口

---

## 核心代码走读

### 走读路线 1：从 Policy 到 eBPF Map

```
pkg/policy/v1beta1/policy_file.go
    └── PoliciesFromPaths()
        └── getPoliciesFromFile()
            └── yaml.Unmarshal()

pkg/policy/policy.go
    └── Policy struct
    └── NewPolicy()

pkg/policy/ebpf.go
    └── updateBPF()
        ├── computeFilterEqualities()
        ├── createNewFilterMapsVersion()
        ├── updateUIntFilterBPF()
        ├── updateStringFilterBPF()
        └── computePoliciesConfig()
```

### 走读路线 2：内核态过滤执行

```
pkg/ebpf/c/common/filtering.h
    └── evaluate_scope_filters()
        └── match_scope_filters()
            ├── bool_filter_matches()
            ├── uint_filter_range_matches()
            ├── equality_filter_matches()
            └── binary_filter_matches()

    └── evaluate_data_filters()
        └── match_data_filters()
            ├── get_event_filter_map()
            └── equality_filter_matches()
```

### 走读路线 3：用户态过滤执行

```
pkg/filters/scope.go
    └── ScopeFilter.Filter()
        ├── containerFilter.Filter()
        ├── processNameFilter.Filter()
        ├── uidFilter.Filter()
        └── ... 其他过滤器

pkg/filters/data.go
    └── DataFilter.Filter()
        ├── 检查内核过滤状态
        └── 执行用户态过滤

pkg/filters/string.go
    └── StringFilter.filter()
        ├── 精确匹配
        ├── 前缀匹配
        ├── 后缀匹配
        └── 包含匹配
```

### 关键数据结构

```c
// pkg/ebpf/c/types.h

// 事件上下文
typedef struct event_context {
    u64 ts;
    task_context_t task;
    u32 eventid;
    s32 syscall;
    s64 retval;
    u32 stack_id;
    u16 processor_id;
    u16 policies_version;      // 策略版本
    u64 matched_policies;      // 匹配的策略位图
} event_context_t;

// 等式结构
typedef struct equality {
    u64 equals_in_policies;     // "=" 操作的策略位图
    u64 key_used_in_policies;   // 使用该 key 的策略位图
} eq_t;

// 策略配置
typedef struct policies_config {
    u64 uid_filter_enabled;     // UID 过滤启用位图
    u64 uid_filter_match_if_key_missing;  // key 缺失时匹配位图
    // ... 其他过滤器
    u64 enabled_policies;       // 启用的策略位图
} policies_config_t;

// 事件配置
typedef struct event_config {
    u64 submit_for_policies;    // 需要提交该事件的策略位图
    u64 field_types;            // 字段类型编码
    data_filter_config_t data_filter;  // 数据过滤配置
} event_config_t;
```

---

## 总结

Tracee 的事件过滤机制是一个精心设计的双层架构：

1. **内核态过滤**：
   - 使用 eBPF Maps 存储过滤规则
   - 位图操作支持 64 个策略并发处理
   - 版本化 Maps 支持热更新
   - LPM Trie 支持高效的前缀/后缀匹配

2. **用户态过滤**：
   - 处理复杂的过滤逻辑
   - 支持容器和 Kubernetes 元数据
   - 灵活的 Filter 接口设计

3. **Policy 系统**：
   - 声明式的 YAML 配置
   - Scope 过滤定义监控范围
   - Event 过滤定义事件细节

理解这个机制对于：
- 编写高效的 Policy
- 调优 Tracee 性能
- 扩展 Tracee 功能

都至关重要。

---

## 参考资源

- [Tracee 官方文档](https://aquasecurity.github.io/tracee/)
- [eBPF Maps 文档](https://docs.kernel.org/bpf/maps.html)
- [LPM Trie 文档](https://docs.kernel.org/bpf/map_lpm_trie.html)
- [Tracee GitHub 仓库](https://github.com/aquasecurity/tracee)
