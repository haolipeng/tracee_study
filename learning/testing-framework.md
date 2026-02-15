# Tracee 测试框架详解

> 预估学习时长：2-3天 | 难度：⭐⭐⭐ (中高级)

## 概述

Tracee 拥有一个成熟且完善的测试体系，涵盖单元测试、集成测试、端到端测试 (E2E)、性能测试等多个层次。这个测试框架确保了 Tracee 在不同内核版本、不同架构 (x86_64/ARM64) 上的稳定性和可靠性。

### 学习目标

完成本章学习后，你将能够：

1. 理解 Tracee 的多层测试架构设计
2. 掌握 Go 语言测试的最佳实践（表驱动测试、Mock、Stub）
3. 学会为 Tracee 编写单元测试和集成测试
4. 理解 E2E 测试中的事件触发与验证机制
5. 掌握性能测试与基准测试 (Benchmark) 的编写方法
6. 了解 CI/CD 中的自动化测试流程

---

## 1. 测试体系架构

### 1.1 架构总览

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         Tracee 测试体系架构                              │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                    CI/CD Pipeline (GitHub Actions)               │   │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐  │   │
│  │  │ Code Verify │  │   Lint      │  │  Static Analysis        │  │   │
│  │  │ (fmt, vet)  │  │  (revive)   │  │  (staticcheck, errcheck)│  │   │
│  │  └─────────────┘  └─────────────┘  └─────────────────────────┘  │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                    │                                    │
│                                    ▼                                    │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                        单元测试 (Unit Tests)                     │   │
│  │  ┌───────────────┐  ┌───────────────┐  ┌───────────────────┐   │   │
│  │  │ pkg/*_test.go │  │ cmd/*_test.go │  │ common/*_test.go  │   │   │
│  │  │ (核心模块测试) │  │ (命令行测试)   │  │  (通用库测试)      │   │   │
│  │  └───────────────┘  └───────────────┘  └───────────────────┘   │   │
│  │                                                                 │   │
│  │  make test-unit | make test-types | make test-common            │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                    │                                    │
│                                    ▼                                    │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                      集成测试 (Integration Tests)                 │   │
│  │  ┌─────────────────────────────────────────────────────────┐    │   │
│  │  │              tests/integration/*_test.go                 │    │   │
│  │  │  • event_filters_test.go (事件过滤测试)                  │    │   │
│  │  │  • dependencies_test.go  (依赖关系测试)                  │    │   │
│  │  │  • capture_test.go       (捕获功能测试)                  │    │   │
│  │  └─────────────────────────────────────────────────────────┘    │   │
│  │                                                                 │   │
│  │  make test-integration (需要 root 权限和 eBPF 环境)              │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                    │                                    │
│                                    ▼                                    │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                    E2E 测试 (End-to-End Tests)                   │   │
│  │  ┌───────────────────┐  ┌───────────────────────────────────┐   │   │
│  │  │ e2e-inst-test.sh  │  │ tests/e2e-inst-signatures/        │   │   │
│  │  │ (Instrumentation) │  │ • e2e-vfs_write.go                │   │   │
│  │  │                   │  │ • e2e-hooked_syscall.go           │   │   │
│  │  └───────────────────┘  └───────────────────────────────────┘   │   │
│  │  ┌───────────────────┐  ┌───────────────────────────────────┐   │   │
│  │  │ e2e-net-test.sh   │  │ tests/e2e-net-signatures/         │   │   │
│  │  │ (Network)         │  │ • e2e-http.go                     │   │   │
│  │  │                   │  │ • e2e-dns.go                      │   │   │
│  │  └───────────────────┘  └───────────────────────────────────┘   │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                    │                                    │
│                                    ▼                                    │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                      性能测试 (Performance Tests)                 │   │
│  │  ┌───────────────────────────────────────────────────────────┐  │   │
│  │  │               tests/perftests/metrics_test.go              │  │   │
│  │  │               *_bench_test.go (Benchmark 测试)             │  │   │
│  │  └───────────────────────────────────────────────────────────┘  │   │
│  │                                                                 │   │
│  │  make test-performance                                          │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### 1.2 目录结构

```
tracee/
├── tests/
│   ├── integration/           # 集成测试
│   │   ├── event_filters_test.go
│   │   ├── dependencies_test.go
│   │   ├── capture_test.go
│   │   ├── tracee.go          # 测试辅助函数
│   │   └── syscaller/         # 系统调用触发工具
│   │       └── cmd/
│   │           ├── syscaller.go
│   │           └── syscall.go
│   ├── e2e-inst-signatures/   # E2E Instrumentation 签名测试
│   │   ├── e2e-vfs_write.go
│   │   ├── e2e-hooked_syscall.go
│   │   ├── export.go
│   │   └── scripts/           # 触发脚本
│   ├── e2e-net-signatures/    # E2E 网络签名测试
│   │   ├── e2e-http.go
│   │   └── scripts/
│   ├── perftests/             # 性能测试
│   │   └── metrics_test.go
│   ├── testutils/             # 测试工具库
│   │   ├── tracee.go
│   │   ├── exec.go
│   │   ├── cpu.go
│   │   └── policies.go
│   ├── policies/              # 测试策略文件
│   │   ├── inst/
│   │   ├── net/
│   │   └── kernel/
│   ├── e2e-inst-test.sh       # E2E Instrumentation 测试脚本
│   └── e2e-net-test.sh        # E2E 网络测试脚本
├── common/
│   ├── tests/                 # 通用测试辅助
│   │   └── helpers.go
│   └── */*_test.go            # 各模块单元测试
├── pkg/
│   └── */*_test.go            # 核心包单元测试
├── signatures/
│   ├── golang/*_test.go       # 签名规则测试
│   └── signaturestest/        # 签名测试框架
│       └── signaturestest.go
└── Makefile                   # 测试命令入口
```

---

## 2. 单元测试

### 2.1 测试文件组织

Tracee 遵循 Go 语言的测试惯例，测试文件与源文件放在同一目录，以 `_test.go` 结尾。

**命名规范**：
- 单元测试：`xxx_test.go`
- 基准测试：`xxx_bench_test.go`

```go
// 文件：pkg/events/core_test.go
package events

import (
    "testing"
    "github.com/stretchr/testify/assert"
)

func TestAllEventsHaveVersion(t *testing.T) {
    t.Parallel()  // 启用并行测试

    for _, event := range CoreEvents {
        _, err := semver.StrictNewVersion(event.version.String())
        assert.NoError(t, err, "event %s has invalid version", event.name)
    }
}
```

### 2.2 测试工具与断言库

Tracee 主要使用以下测试工具：

#### testify 断言库

```go
import (
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

func TestExample(t *testing.T) {
    // assert: 断言失败后继续执行
    assert.Equal(t, expected, actual, "描述信息")
    assert.True(t, condition)
    assert.NoError(t, err)
    assert.Contains(t, collection, element)

    // require: 断言失败后立即终止测试
    require.NoError(t, err)  // 错误时直接 t.Fatal
    require.NotNil(t, obj)
}
```

#### goleak (goroutine 泄漏检测)

```go
import "go.uber.org/goleak"

func TestNoGoroutineLeak(t *testing.T) {
    defer goleak.VerifyNone(t)  // 测试结束时验证无 goroutine 泄漏

    // 测试代码...
}
```

### 2.3 表驱动测试模式

Tracee 广泛使用表驱动测试 (Table-Driven Tests)，这是 Go 社区推荐的最佳实践：

```go
// 文件：pkg/cmd/flags/policy_test.go
func TestPrepareFilterMapsFromPolicies(t *testing.T) {
    t.Parallel()

    tests := []struct {
        testName           string
        policy             v1beta1.PolicyFile
        expPolicyScopeMap  PolicyScopeMap
        expPolicyEventMap  PolicyEventMap
        skipPolicyCreation bool
    }{
        {
            testName: "global scope - single event",
            policy: v1beta1.PolicyFile{
                Metadata: v1beta1.Metadata{
                    Name: "global-scope-single-event",
                },
                Spec: k8s.PolicySpec{
                    Scope:          []string{"global"},
                    DefaultActions: []string{"log"},
                    Rules: []k8s.Rule{
                        {Event: "write"},
                    },
                },
            },
            expPolicyScopeMap: PolicyScopeMap{
                0: {
                    policyName: "global-scope-single-event",
                    scopeFlags: []scopeFlag{},
                },
            },
            // ...
        },
        {
            testName: "uid scope",
            policy: v1beta1.PolicyFile{
                // ...
            },
            // ...
        },
    }

    for _, tc := range tests {
        tc := tc  // 捕获循环变量 (Go 1.22 前需要)

        t.Run(tc.testName, func(t *testing.T) {
            t.Parallel()

            // 执行测试逻辑
            result, err := prepareFilterMapsFromPolicies(tc.policy)
            require.NoError(t, err)
            assert.Equal(t, tc.expPolicyScopeMap, result.scopeMap)
            assert.Equal(t, tc.expPolicyEventMap, result.eventMap)
        })
    }
}
```

### 2.4 Mock 与 Stub 使用

#### 接口 Mock

Tracee 通过定义接口来实现可测试性，测试时可以使用 Mock 实现：

```go
// 文件：pkg/ebpf/controlplane/controlplane_test.go

// createTestController 创建测试用的 Controller，不需要真实的 BPF 设置
func createTestController() *controlplane.Controller {
    dataPresentor := bufferdecoder.NewTypeDecoder()

    // 使用 nil 模块创建控制器，避免 BPF 设置问题
    ctrl := controlplane.NewController(
        &libbpfgo.Module{},  // Mock 的 BPF 模块
        nil,
        false,
        nil,
        dataPresentor,
    )

    return ctrl
}

func TestControlPlane_SignalHandlerExecution(t *testing.T) {
    ctrl := createTestController()

    // 注册自定义信号处理器
    customSignalHandlers := map[events.ID]controlplane.SignalHandler{
        events.VfsWrite: func(signalID events.ID, args []trace.Argument) error {
            return nil
        },
    }

    err := ctrl.RegisterSignal(customSignalHandlers)
    require.NoError(t, err)

    // 测试信号处理
    // ...
}
```

#### 签名测试的 FindingsHolder

```go
// 文件：signatures/signaturestest/signaturestest.go

// FindingsHolder 用于收集签名检测结果
type FindingsHolder struct {
    Values []*detect.Finding
}

func (h *FindingsHolder) OnFinding(f *detect.Finding) {
    h.Values = append(h.Values, f)
}

func (h *FindingsHolder) GroupBySigID() map[string]*detect.Finding {
    r := make(map[string]*detect.Finding)
    for _, v := range h.Values {
        r[v.SigMetadata.ID] = v
    }
    return r
}
```

**使用示例**：

```go
// 文件：signatures/golang/disk_mount_test.go
func TestDiskMount(t *testing.T) {
    t.Parallel()

    testCases := []struct {
        Name     string
        Events   []trace.Event
        Findings map[string]*detect.Finding
    }{
        {
            Name: "should trigger detection",
            Events: []trace.Event{
                {
                    ProcessName:  "mal",
                    EventName:    "security_sb_mount",
                    ContextFlags: trace.ContextFlags{ContainerStarted: true},
                    Args: []trace.Argument{
                        {
                            ArgMeta: trace.ArgMeta{Name: "dev_name"},
                            Value:   "/dev/sda1",
                        },
                    },
                },
            },
            Findings: map[string]*detect.Finding{
                "TRC-1014": {/* 期望的检测结果 */},
            },
        },
    }

    for _, tc := range testCases {
        t.Run(tc.Name, func(t *testing.T) {
            t.Parallel()

            // 创建 FindingsHolder 作为回调收集器
            holder := signaturestest.FindingsHolder{}
            sig := DiskMount{}
            sig.Init(detect.SignatureContext{Callback: holder.OnFinding})

            // 发送事件
            for _, e := range tc.Events {
                err := sig.OnEvent(e.ToProtocol())
                require.NoError(t, err)
            }

            // 验证结果
            assert.Equal(t, tc.Findings, holder.GroupBySigID())
        })
    }
}
```

### 2.5 测试辅助工具

```go
// 文件：common/tests/helpers.go

// CreateTempFile 创建临时测试文件
func CreateTempFile(tb testing.TB, content string) *os.File {
    tb.Helper()

    file, err := os.CreateTemp("", "test_temp_file_*.txt")
    if err != nil {
        tb.Fatalf("Failed to create temp file: %v", err)
    }
    if _, err := file.WriteString(content); err != nil {
        tb.Fatalf("Failed to write to temp file: %v", err)
    }
    if err := file.Close(); err != nil {
        tb.Fatalf("Failed to close temp file: %v", err)
    }

    return file
}

// PrintStructSizes 打印结构体大小（用于内存布局分析）
func PrintStructSizes(tb testing.TB, w io.Writer, structure interface{}) {
    tb.Helper()
    // ...
}
```

---

## 3. 集成测试 (Integration Tests)

### 3.1 测试环境准备

集成测试需要完整的 Tracee 运行环境：

**环境要求**：
- root 权限 (eBPF 需要)
- Linux 内核 5.x+
- 已编译的 Tracee 二进制

```go
// 文件：tests/integration/tracee.go

// assureIsRoot 确保测试以 root 身份运行
func assureIsRoot(t *testing.T) {
    if syscall.Geteuid() != 0 {
        t.Skipf("***** %s must be run as ROOT *****", t.Name())
    }
}
```

### 3.2 Tracee 生命周期管理

```go
// 文件：tests/integration/tracee.go

// startTracee 启动 Tracee 进程
func startTracee(ctx context.Context, t *testing.T, cfg config.Config,
                 output *config.OutputConfig, capture *config.CaptureConfig) (*tracee.Tracee, error) {
    // 初始化 libbpfgo 回调
    initialize.SetLibbpfgoCallbacks()

    // 获取内核配置
    kernelConfig, err := initialize.KernelConfig()
    if err != nil {
        return nil, err
    }
    cfg.KernelConfig = kernelConfig

    // 初始化 BPF 对象
    osInfo, _ := environment.GetOSInfo()
    err = initialize.BpfObject(&cfg, kernelConfig, osInfo, "/tmp/tracee", "")
    if err != nil {
        return nil, err
    }

    // 配置缓冲区
    cfg.PerfBufferSize = (4096 * 1024) / os.Getpagesize()
    cfg.PipelineChannelSize = 10000

    // 创建并初始化 Tracee
    trc, err := tracee.New(cfg)
    if err != nil {
        return nil, err
    }

    err = trc.Init(ctx)
    if err != nil {
        return nil, err
    }

    // 在 goroutine 中运行
    go func() {
        _ = trc.Run(ctx)
    }()

    return trc, nil
}

// waitForTraceeStart 等待 Tracee 启动完成
func waitForTraceeStart(trc *tracee.Tracee) error {
    const timeout = 10 * time.Second

    for {
        select {
        case <-time.After(1 * time.Second):
            if trc.Running() {
                return nil
            }
        case <-time.After(timeout):
            return errors.New("timed out on waiting for tracee to start")
        }
    }
}
```

### 3.3 事件过滤测试

```go
// 文件：tests/integration/event_filters_test.go

func Test_EventFilters(t *testing.T) {
    assureIsRoot(t)
    defer goleak.VerifyNone(t)

    tt := []testCase{
        {
            name: "container: event: trace only events from new containers",
            policyFiles: []testutils.PolicyFileWithID{
                {
                    Id: 1,
                    PolicyFile: v1beta1.PolicyFile{
                        Metadata: v1beta1.Metadata{
                            Name: "container-event",
                        },
                        Spec: k8s.PolicySpec{
                            Scope: []string{"container=new"},
                            DefaultActions: []string{"log"},
                            Rules: []k8s.Rule{
                                {Event: "-container_create"},
                                {Event: "-container_remove"},
                            },
                        },
                    },
                },
            },
            cmdEvents: []cmdEvents{
                newCmdEvents(
                    "docker run -d --rm hello-world",
                    0,
                    10*time.Second,
                    []trace.Event{
                        expectEvent(anyHost, "hello", anyProcessorID, 1, 0,
                            events.SchedProcessExec, orPolNames("container-event"), orPolIDs(1)),
                    },
                    []string{},
                ),
            },
            useSyscaller: false,
            test:         ExpectAllInOrderSequentially,
        },
        // 更多测试用例...
    }

    for _, tc := range tt {
        t.Run(tc.name, func(t *testing.T) {
            // 执行测试...
        })
    }
}
```

### 3.4 系统调用触发工具 (Syscaller)

Syscaller 是一个专门的工具，用于在测试中精确触发特定的系统调用：

```go
// 文件：tests/integration/syscaller/cmd/syscaller.go

func main() {
    // 将进程绑定到特定 CPU
    err := testutils.PinProccessToCPU()
    if err != nil {
        os.Exit(1)
    }
    runtime.LockOSThread()
    defer runtime.UnlockOSThread()

    // 解析参数
    callerComm := os.Args[1]
    syscallsToCall := make([]events.ID, 0)
    for _, arg := range os.Args[2:] {
        syscallNum, _ := strconv.Atoi(arg)
        syscallsToCall = append(syscallsToCall, events.ID(syscallNum))
    }

    // 更改进程名称
    changeOwnComm(callerComm)

    // 执行系统调用
    errs := callsys(syscallsToCall)
}
```

---

## 4. E2E 测试 (End-to-End Tests)

### 4.1 E2E 测试概述

E2E 测试验证 Tracee 在真实环境中的完整工作流程，包括：
- Instrumentation 事件检测
- 网络事件检测
- 签名规则触发

### 4.2 E2E Instrumentation 测试

#### 测试架构

```
┌──────────────────────────────────────────────────────────────────┐
│                    E2E Instrumentation 测试流程                   │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. 编译并启动 Tracee                                            │
│     ┌──────────────────────────────────────────────────────┐    │
│     │  ./dist/tracee --signatures-dir ... --policy ...     │    │
│     └──────────────────────────────────────────────────────┘    │
│                            │                                     │
│                            ▼                                     │
│  2. 加载 E2E 签名插件                                            │
│     ┌──────────────────────────────────────────────────────┐    │
│     │  dist/e2e-inst-signatures/builtin.so                 │    │
│     │  • e2eVfsWrite                                        │    │
│     │  • e2eHookedSyscall                                   │    │
│     │  • e2eContainersDataSource                            │    │
│     └──────────────────────────────────────────────────────┘    │
│                            │                                     │
│                            ▼                                     │
│  3. 执行触发脚本                                                 │
│     ┌──────────────────────────────────────────────────────┐    │
│     │  scripts/vfs_write.sh                                │    │
│     │  → touch vfs_write.txt && echo "content" >> ...      │    │
│     └──────────────────────────────────────────────────────┘    │
│                            │                                     │
│                            ▼                                     │
│  4. 验证检测结果                                                 │
│     ┌──────────────────────────────────────────────────────┐    │
│     │  检查输出文件中是否包含期望的事件名称                    │    │
│     │  cat $outputfile | jq .eventName | grep "VFS_WRITE"  │    │
│     └──────────────────────────────────────────────────────┘    │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

#### E2E 签名示例

```go
// 文件：tests/e2e-inst-signatures/e2e-vfs_write.go

type e2eVfsWrite struct {
    cb detect.SignatureHandler
}

func (sig *e2eVfsWrite) Init(ctx detect.SignatureContext) error {
    sig.cb = ctx.Callback
    return nil
}

func (sig *e2eVfsWrite) GetMetadata() (detect.SignatureMetadata, error) {
    return detect.SignatureMetadata{
        ID:          "VFS_WRITE",
        EventName:   "VFS_WRITE",
        Version:     "0.1.0",
        Name:        "Vfs Write Test",
        Description: "Instrumentation events E2E Tests: Vfs Write",
        Tags:        []string{"e2e", "instrumentation"},
    }, nil
}

func (sig *e2eVfsWrite) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
    return []detect.SignatureEventSelector{
        {Source: "tracee", Name: "vfs_write"},
    }, nil
}

func (sig *e2eVfsWrite) OnEvent(event protocol.Event) error {
    eventObj, ok := event.Payload.(trace.Event)
    if !ok {
        return errors.New("failed to cast event's payload")
    }

    switch eventObj.EventName {
    case "vfs_write":
        filePath, err := eventObj.GetStringArgumentByName("pathname")
        if err != nil {
            return err
        }

        // 检查是否为测试期望的文件
        if !strings.HasSuffix(filePath, "/vfs_write.txt") {
            return nil
        }

        // 触发检测
        m, _ := sig.GetMetadata()
        sig.cb(&detect.Finding{
            SigMetadata: m,
            Event:       event,
            Data:        map[string]interface{}{},
        })
    }

    return nil
}
```

#### 触发脚本

```bash
#!/bin/bash
# 文件：tests/e2e-inst-signatures/scripts/vfs_write.sh

exit_err() {
    echo -n "ERROR: "
    echo $@
    exit 1
}

touch vfs_write.txt
`which echo` write content >> vfs_write.txt || exit_err "failed writing to file"
```

#### 测试策略文件

```yaml
# 文件：tests/policies/inst/vfs_write.yaml
apiVersion: tracee.aquasec.com/v1beta1
kind: Policy
metadata:
  name: vfs-write-test
  annotations:
    description: test tracee's vfs write events
spec:
  scope:
    - comm=echo,write
  rules:
    - event: VFS_WRITE
```

### 4.3 E2E 测试脚本

```bash
#!/bin/bash
# 文件：tests/e2e-inst-test.sh

# 环境检查
if [[ $UID -ne 0 ]]; then
    error_exit "need root privileges"
fi

# 编译 Tracee 和测试签名
make -j"$(nproc)" all
make e2e-inst-signatures

# 启动 Tracee
tracee_command="./dist/tracee \
    --install-path $TRACEE_TMP_DIR \
    --proctree source=both \
    --output json:$outputfile \
    --signatures-dir $SIG_DIR \
    --policy ./tests/policies/inst/"

eval "$tracee_command &"

# 等待 Tracee 启动
while [[ ! -f $TRACEE_TMP_DIR/tracee.pid ]]; do
    sleep 1
done

# 运行测试
for TEST in $TESTS; do
    "${TESTS_DIR}"/"${TEST,,}".sh
done

# 停止 Tracee
kill -SIGINT "${tracee_pids[@]}"

# 验证结果
for TEST in $TESTS; do
    cat $outputfile | jq .eventName | grep -q "$TEST" && found=1
    if [[ $found -eq 1 ]]; then
        echo "$TEST: SUCCESS"
    else
        echo "$TEST: FAILED"
    fi
done
```

### 4.4 签名导出

```go
// 文件：tests/e2e-inst-signatures/export.go

var ExportedSignatures = []detect.Signature{
    &e2eProcessExecuteFailed{},
    &e2eVfsWrite{},
    &e2eVfsWritev{},
    &e2eFileModification{},
    &e2eSecurityInodeRename{},
    &e2eContainersDataSource{},
    &e2eBpfAttach{},
    &e2eProcessTreeDataSource{},
    &e2eHookedSyscall{},
    &e2eSignatureDerivation{},
    &e2eDnsDataSource{},
    &e2eWritableDatasourceSig{},
    &e2eSecurityPathNotify{},
    &e2eSetFsPwd{},
    &e2eFtraceHook{},
    &e2eSuspiciousSyscallSource{},
    &e2eStackPivot{},
    &e2eLsm{},
}

var ExportedDataSources = []detect.DataSource{
    datasourcetest.New(),
}
```

---

## 5. 性能测试

### 5.1 Benchmark 测试

Go 的 benchmark 测试用于测量代码性能：

```go
// 文件：common/bucketcache/bucketcache_bench_test.go

func BenchmarkAddBucketItemCurrent(b *testing.B) {
    bc := &BucketCache{}
    bc.Init(100)

    start := make(chan struct{})
    var wg sync.WaitGroup
    wg.Add(1000 * b.N)

    for i := 0; i < 1000*b.N; i++ {
        go func() {
            <-start
            defer wg.Done()
            for j := 0; j < 100; j++ {
                bc.addBucketItem(uint32(j), uint32(j), false)
            }
        }()
    }

    b.ResetTimer()  // 重置计时器，排除初始化时间
    close(start)
    wg.Wait()
    b.StopTimer()
}
```

**常见的 Benchmark 测试文件**：
- `common/bucketcache/bucketcache_bench_test.go` - 缓存性能
- `common/proc/stat_bench_test.go` - 进程信息读取性能
- `pkg/ebpf/events_pipeline_bench_test.go` - 事件管道性能
- `pkg/events/parse_args_bench_test.go` - 参数解析性能

### 5.2 Metrics 测试

```go
// 文件：tests/perftests/metrics_test.go

var metrics = []string{
    "tracee_ebpf_bpf_logs_total",
    "tracee_ebpf_errors_total",
    "tracee_ebpf_events_filtered",
    "tracee_ebpf_events_total",
    "tracee_ebpf_lostevents_total",
}

func TestMetricsAndPprofExist(t *testing.T) {
    defer goleak.VerifyNone(t)

    if !testutils.IsSudoCmdAvailableForThisUser() {
        t.Skip("skipping: sudo command is not available")
    }

    cmd := "--output none --events=syslog --server metrics --server pprof"
    running := testutils.NewRunningTracee(context.Background(), cmd)

    ready, runErr := running.Start(testutils.TraceeDefaultStartupTimeout)
    require.NoError(t, runErr)
    defer running.Stop()

    r := <-ready
    switch r {
    case testutils.TraceeFailed:
        t.Fatal("tracee failed to start")
    case testutils.TraceeTimedout:
        t.Fatal("tracee timedout to start")
    }

    // 验证 metrics 端点
    metricsErr := checkIfMetricsExist(metrics)
    pprofErr := checkIfPprofExist()

    require.NoError(t, metricsErr)
    require.NoError(t, pprofErr)
}
```

---

## 6. 测试运行方式

### 6.1 Makefile 命令

```makefile
# 单元测试
make test-unit                          # 运行所有单元测试
make test-unit PKG=pkg/events           # 运行特定包的测试
make test-unit TEST=TestEventFilters    # 运行特定测试函数
make test-unit PKG=pkg/events TEST=TestCore  # 组合使用

# 模块测试
make test-types                         # 运行 types 模块测试
make test-common                        # 运行 common 模块测试

# 集成测试
make test-integration                   # 运行集成测试 (需要 root)
make test-integration TEST=Test_EventFilters  # 运行特定集成测试

# 性能测试
make test-performance                   # 运行性能测试

# 代码覆盖率
make coverage                           # 生成覆盖率报告
make coverage-html                      # 生成 HTML 覆盖率报告
```

### 6.2 底层 go test 命令

```bash
# 单元测试
go test -tags core,ebpf -short -race -shuffle on -failfast -v ./pkg/...

# 带覆盖率
go test -coverprofile=coverage.txt -covermode=atomic ./...

# Benchmark 测试
go test -bench=. -benchmem ./common/bucketcache/

# 集成测试
go test -tags core,ebpf -timeout 20m -race -v -p 1 ./tests/integration/...
```

### 6.3 常用测试标志

| 标志 | 说明 |
|------|------|
| `-short` | 跳过长时间运行的测试 |
| `-race` | 启用竞态检测 |
| `-shuffle on` | 随机化测试顺序 |
| `-failfast` | 第一个失败后停止 |
| `-v` | 详细输出 |
| `-p 1` | 禁用并行（集成测试需要） |
| `-count=1` | 禁用测试缓存 |
| `-timeout 20m` | 设置超时时间 |

---

## 7. CI/CD 中的测试流程

### 7.1 GitHub Actions 工作流

```yaml
# 文件：.github/workflows/pr.yaml

name: PR
on:
  pull_request:
    branches: ["main"]

jobs:
  # 代码验证
  verify-analyze-code:
    runs-on: ubuntu-24.04
    steps:
      - name: Lint
        run: make check-lint
      - name: Check Code Style
        run: make check-fmt
      - name: Check with StaticCheck
        run: make check-staticcheck

  # 单元测试
  unit-tests:
    runs-on: ubuntu-24.04
    steps:
      - name: Run Full Unit Test Suite
        run: make test-unit
      - name: Upload Coverage
        uses: codecov/codecov-action@v5
        with:
          files: ./coverage.txt

  # 集成测试
  integration-tests:
    runs-on: ubuntu-24.04
    container:
      image: ubuntu:24.04
      options: --privileged
    steps:
      - name: Run Integration Tests
        run: make test-integration

  # 性能测试
  performance-tests:
    runs-on: ubuntu-24.04
    container:
      options: --privileged
    steps:
      - name: Run Performance Tests
        run: make test-performance
```

### 7.2 多内核版本测试矩阵

CI/CD 会在多个内核版本上运行测试：

```yaml
# 测试矩阵示例
matrix:
  - name: "GKE 5.4"
  - name: "GKE 5.10"
  - name: "GKE 5.15"
  - name: "AMZN2 5.10"
  - name: "RHEL8 4.18"
  - name: "Ubuntu Focal 5.4"
  - name: "Ubuntu Jammy 5.15"
  - name: "Ubuntu Noble 6.8"
```

### 7.3 架构支持

- **x86_64**: 完整测试
- **ARM64**: 部分测试（跳过某些不兼容的测试）

---

## 8. 如何为新功能编写测试

### 8.1 单元测试编写步骤

```go
// 1. 创建测试文件: pkg/myfeature/myfeature_test.go
package myfeature

import (
    "testing"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

// 2. 使用表驱动测试
func TestMyNewFunction(t *testing.T) {
    t.Parallel()  // 如果测试是独立的，启用并行

    tests := []struct {
        name     string
        input    string
        expected string
        wantErr  bool
    }{
        {
            name:     "valid input",
            input:    "hello",
            expected: "HELLO",
            wantErr:  false,
        },
        {
            name:     "empty input",
            input:    "",
            expected: "",
            wantErr:  true,
        },
    }

    for _, tc := range tests {
        tc := tc
        t.Run(tc.name, func(t *testing.T) {
            t.Parallel()

            result, err := MyNewFunction(tc.input)

            if tc.wantErr {
                require.Error(t, err)
                return
            }

            require.NoError(t, err)
            assert.Equal(t, tc.expected, result)
        })
    }
}
```

### 8.2 集成测试编写步骤

```go
// 文件：tests/integration/mynewfeature_test.go

func Test_MyNewFeature(t *testing.T) {
    // 1. 确保以 root 运行
    assureIsRoot(t)

    // 2. 检查 goroutine 泄漏
    defer goleak.VerifyNone(t)

    // 3. 准备测试配置
    cfg := config.Config{
        // 配置...
    }

    // 4. 启动 Tracee
    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()

    trc, err := startTracee(ctx, t, cfg, nil, nil)
    require.NoError(t, err)

    err = waitForTraceeStart(trc)
    require.NoError(t, err)

    // 5. 执行测试操作
    // ...

    // 6. 收集和验证事件
    // ...
}
```

### 8.3 E2E 签名测试编写步骤

```go
// 1. 创建签名文件: tests/e2e-inst-signatures/e2e-my_feature.go

type e2eMyFeature struct {
    cb detect.SignatureHandler
}

func (sig *e2eMyFeature) Init(ctx detect.SignatureContext) error {
    sig.cb = ctx.Callback
    return nil
}

func (sig *e2eMyFeature) GetMetadata() (detect.SignatureMetadata, error) {
    return detect.SignatureMetadata{
        ID:          "MY_FEATURE",
        EventName:   "MY_FEATURE",
        Version:     "0.1.0",
        Name:        "My Feature Test",
        Description: "E2E test for my feature",
        Tags:        []string{"e2e"},
    }, nil
}

func (sig *e2eMyFeature) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
    return []detect.SignatureEventSelector{
        {Source: "tracee", Name: "my_event"},
    }, nil
}

func (sig *e2eMyFeature) OnEvent(event protocol.Event) error {
    // 检测逻辑...
    sig.cb(&detect.Finding{...})
    return nil
}

// 2. 在 export.go 中注册
var ExportedSignatures = []detect.Signature{
    // ...
    &e2eMyFeature{},
}

// 3. 创建触发脚本: tests/e2e-inst-signatures/scripts/my_feature.sh

// 4. 创建策略文件: tests/policies/inst/my_feature.yaml

// 5. 在 e2e-inst-test.sh 中添加测试
```

---

## 9. 动手练习

### 练习 1: 编写单元测试

为以下函数编写完整的单元测试：

```go
// pkg/utils/validator.go
package utils

import "errors"

func ValidateEventName(name string) error {
    if name == "" {
        return errors.New("event name cannot be empty")
    }
    if len(name) > 64 {
        return errors.New("event name too long")
    }
    for _, c := range name {
        if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
             (c >= '0' && c <= '9') || c == '_') {
            return errors.New("invalid character in event name")
        }
    }
    return nil
}
```

**要求**：
1. 使用表驱动测试
2. 覆盖所有边界情况
3. 使用 testify 断言

<details>
<summary>参考答案</summary>

```go
package utils

import (
    "testing"
    "github.com/stretchr/testify/assert"
)

func TestValidateEventName(t *testing.T) {
    t.Parallel()

    tests := []struct {
        name    string
        input   string
        wantErr bool
        errMsg  string
    }{
        {"valid lowercase", "sched_process_exec", false, ""},
        {"valid uppercase", "SCHED_PROCESS_EXEC", false, ""},
        {"valid mixed", "Sched_Process_Exec", false, ""},
        {"valid with numbers", "event123", false, ""},
        {"empty string", "", true, "event name cannot be empty"},
        {"too long", string(make([]byte, 65)), true, "event name too long"},
        {"exactly 64 chars", string(make([]byte, 64)), false, ""},
        {"invalid dash", "sched-process-exec", true, "invalid character"},
        {"invalid space", "sched process", true, "invalid character"},
        {"invalid unicode", "event_name_中文", true, "invalid character"},
    }

    for _, tc := range tests {
        tc := tc
        t.Run(tc.name, func(t *testing.T) {
            t.Parallel()

            err := ValidateEventName(tc.input)

            if tc.wantErr {
                assert.Error(t, err)
                if tc.errMsg != "" {
                    assert.Contains(t, err.Error(), tc.errMsg)
                }
            } else {
                assert.NoError(t, err)
            }
        })
    }
}
```

</details>

### 练习 2: 编写 Benchmark 测试

为一个字符串处理函数编写 benchmark 测试，比较两种实现的性能：

```go
// 实现 1: 使用 strings.Builder
func JoinWithBuilder(parts []string, sep string) string {
    var b strings.Builder
    for i, p := range parts {
        if i > 0 {
            b.WriteString(sep)
        }
        b.WriteString(p)
    }
    return b.String()
}

// 实现 2: 使用 + 拼接
func JoinWithConcat(parts []string, sep string) string {
    result := ""
    for i, p := range parts {
        if i > 0 {
            result += sep
        }
        result += p
    }
    return result
}
```

<details>
<summary>参考答案</summary>

```go
package utils

import (
    "testing"
)

func BenchmarkJoinWithBuilder(b *testing.B) {
    parts := []string{"part1", "part2", "part3", "part4", "part5"}
    sep := ","

    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        _ = JoinWithBuilder(parts, sep)
    }
}

func BenchmarkJoinWithConcat(b *testing.B) {
    parts := []string{"part1", "part2", "part3", "part4", "part5"}
    sep := ","

    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        _ = JoinWithConcat(parts, sep)
    }
}

// 运行: go test -bench=. -benchmem
```

</details>

### 练习 3: 创建 Mock 测试

为以下接口创建 Mock 并编写测试：

```go
type EventProcessor interface {
    Process(event Event) error
    GetStats() Stats
}

type EventHandler struct {
    processor EventProcessor
}

func (h *EventHandler) Handle(event Event) error {
    return h.processor.Process(event)
}
```

<details>
<summary>参考答案</summary>

```go
package handler

import (
    "errors"
    "testing"
    "github.com/stretchr/testify/assert"
)

// MockEventProcessor 是 EventProcessor 的 Mock 实现
type MockEventProcessor struct {
    ProcessFunc  func(Event) error
    GetStatsFunc func() Stats
    ProcessCalls int
}

func (m *MockEventProcessor) Process(event Event) error {
    m.ProcessCalls++
    if m.ProcessFunc != nil {
        return m.ProcessFunc(event)
    }
    return nil
}

func (m *MockEventProcessor) GetStats() Stats {
    if m.GetStatsFunc != nil {
        return m.GetStatsFunc()
    }
    return Stats{}
}

func TestEventHandler_Handle(t *testing.T) {
    t.Parallel()

    tests := []struct {
        name       string
        setupMock  func() *MockEventProcessor
        event      Event
        wantErr    bool
        wantCalls  int
    }{
        {
            name: "successful processing",
            setupMock: func() *MockEventProcessor {
                return &MockEventProcessor{
                    ProcessFunc: func(e Event) error {
                        return nil
                    },
                }
            },
            event:     Event{Name: "test"},
            wantErr:   false,
            wantCalls: 1,
        },
        {
            name: "processing error",
            setupMock: func() *MockEventProcessor {
                return &MockEventProcessor{
                    ProcessFunc: func(e Event) error {
                        return errors.New("process failed")
                    },
                }
            },
            event:     Event{Name: "test"},
            wantErr:   true,
            wantCalls: 1,
        },
    }

    for _, tc := range tests {
        tc := tc
        t.Run(tc.name, func(t *testing.T) {
            t.Parallel()

            mock := tc.setupMock()
            handler := &EventHandler{processor: mock}

            err := handler.Handle(tc.event)

            if tc.wantErr {
                assert.Error(t, err)
            } else {
                assert.NoError(t, err)
            }
            assert.Equal(t, tc.wantCalls, mock.ProcessCalls)
        })
    }
}
```

</details>

---

## 10. 核心代码走读

### 10.1 测试工具类: testutils

**文件位置**: `tests/testutils/`

#### RunningTracee - Tracee 进程包装器

```go
// 文件：tests/testutils/tracee.go

// RunningTracee 封装了运行中的 Tracee 进程
type RunningTracee struct {
    ctx       context.Context
    cancel    context.CancelFunc
    cmdStatus chan error
    cmdLine   string
    pid       int
    isReady   chan TraceeStatus
}

// Start 启动 Tracee 进程并等待就绪
func (r *RunningTracee) Start(timeout time.Duration) (<-chan TraceeStatus, error) {
    // 检查是否已运行
    if isTraceeAlreadyRunning() {
        // 返回已运行状态
    }

    // 通过 sudo 在后台启动
    r.pid, r.cmdStatus, _ = ExecCmdBgWithSudoAndCtx(r.ctx, r.cmdLine)

    // 轮询健康检查端点
    for {
        if r.IsReady() {
            // 返回启动成功
        }
        if time.Since(now) > timeout {
            // 返回超时
        }
    }
}

// IsReady 通过 HTTP 健康检查判断就绪状态
func (r *RunningTracee) IsReady() bool {
    resp, err := http.Get("http://localhost:3369/healthz")
    return resp.StatusCode == 200
}
```

#### 进程执行工具

```go
// 文件：tests/testutils/exec.go

// ExecCmdBgWithSudoAndCtx 在后台以 sudo 权限执行命令
func ExecCmdBgWithSudoAndCtx(ctx context.Context, command string) (int, chan error, error) {
    // 添加 sudo 前缀
    command = fmt.Sprintf("sudo %s", command)

    // 解析命令
    command, args, _ := ParseCmd(command)

    // 创建命令
    cmd := exec.Command(command, args...)

    // 在独立 goroutine 中启动，并绑��到特定 CPU
    go func() {
        _ = PinProccessToCPU()     // 绑定 CPU
        runtime.LockOSThread()     // 锁定 OS 线程

        cmd.Start()

        go func() {
            cmd.Wait()
        }()
    }()

    // 返回 PID 和状态通道
}

// DiscoverChildProcesses 发现所有子进程
func DiscoverChildProcesses(pid int) ([]int, error) {
    psCmd := exec.Command("pgrep", "-P", fmt.Sprintf("%d", pid))
    // ...
}
```

### 10.2 集成测试框架

```go
// 文件：tests/integration/tracee.go

// eventBuffer 线程安全的事件缓冲区
type eventBuffer struct {
    mu     sync.RWMutex
    events []trace.Event
}

func (b *eventBuffer) addEvent(evt trace.Event) {
    b.mu.Lock()
    defer b.mu.Unlock()
    b.events = append(b.events, evt)
}

// waitForTraceeOutputEvents 等待收集到期望数量的事件
func waitForTraceeOutputEvents(t *testing.T, waitFor time.Duration,
                               actual *eventBuffer, expectedEvts int,
                               failOnTimeout bool) error {
    if waitFor > 0 {
        time.Sleep(waitFor)
    }

    const timeout = 5 * time.Second

    for {
        select {
        case <-time.After(1 * time.Second):
            if actual.len() >= expectedEvts {
                return nil
            }
        case <-time.After(timeout):
            if failOnTimeout {
                return fmt.Errorf("timed out waiting for %d events", expectedEvts)
            }
            return nil
        }
    }
}
```

### 10.3 签名测试框架

```go
// 文件：signatures/signaturestest/signaturestest.go

// FindingsHolder 收集签名检测结果
type FindingsHolder struct {
    Values []*detect.Finding
}

// OnFinding 作为回调函数接收检测结果
func (h *FindingsHolder) OnFinding(f *detect.Finding) {
    h.Values = append(h.Values, f)
}

// GroupBySigID 按签名 ID 分组结果
func (h *FindingsHolder) GroupBySigID() map[string]*detect.Finding {
    r := make(map[string]*detect.Finding)
    for _, v := range h.Values {
        r[v.SigMetadata.ID] = v
    }
    return r
}
```

---

## 11. 最佳实践总结

### 11.1 测试编写原则

1. **表驱动测试**: 使用结构体切片定义测试用例
2. **并行测试**: 独立测试使用 `t.Parallel()`
3. **显式断言**: 使用 testify 的 `assert` 和 `require`
4. **泄漏检测**: 使用 `goleak.VerifyNone()` 检测 goroutine 泄漏
5. **测试隔离**: 每个测试应该独立，不依赖其他测试的状态

### 11.2 命名规范

```go
// 测试函数
func TestFunctionName(t *testing.T)           // 功能测试
func TestFunctionName_SubCase(t *testing.T)   // 子测试
func BenchmarkFunctionName(b *testing.B)      // 基准测试
func ExampleFunctionName()                    // 示例测试

// 辅助函数
func setupTestEnvironment(t *testing.T)       // 设置
func teardownTestEnvironment(t *testing.T)    // 清理
```

### 11.3 常见陷阱

1. **循环变量捕获**: Go 1.22 前需要 `tc := tc`
2. **测试超时**: 集成测试需要增加超时时间
3. **资源清理**: 使用 `defer` 确保资源释放
4. **竞态条件**: 使用 `-race` 标志检测
5. **测试缓存**: 使用 `-count=1` 禁用缓存

---

## 12. 延伸阅读

- [Go Testing 官方文档](https://golang.org/pkg/testing/)
- [testify 项目](https://github.com/stretchr/testify)
- [goleak 项目](https://github.com/uber-go/goleak)
- [Tracee 官方文档](https://aquasecurity.github.io/tracee/)
- [eBPF 测试最佳实践](https://ebpf.io/)

---

## 总结

Tracee 的测试框架展示了如何为复杂的系统级软件构建可靠的测试体系。通过多层次的测试策略（单元测试、集成测试、E2E 测试、性能测试），配合 CI/CD 自动化流程，确保了代码质量和系统稳定性。

掌握这些测试技术，不仅能帮助你理解 Tracee 的工作原理，更能提升你的软件工程实践能力。建议在实际开发中应用这些模式，为你的代码编写完善的测试。
