# Tracee 调试指南

> **学习目标**：掌握 Tracee 项目的调试方法，能够定位和解决开发过程中的常见问题
> **预计时间**：1-2 天
> **难度**：⭐⭐☆☆☆
> **前置知识**：Go 语言基础、eBPF 基本概念、Linux 调试工具使用经验

---

## 目录

1. [概述](#1-概述)
2. [开发环境搭建](#2-开发环境搭建)
3. [用户态代码调试](#3-用户态代码调试)
4. [eBPF 程序调试](#4-ebpf-程序调试)
5. [常见问题排查](#5-常见问题排查)
6. [性能分析工具](#6-性能分析工具)
7. [内存泄漏检测](#7-内存泄漏检测)
8. [动手练习](#8-动手练习)

---

## 1. 概述

### 1.1 学习目标

完成本指南后，你将能够：

- 使用 Delve 调试 Tracee Go 代码
- 配置和使用 Tracee 日志系统进行问题定位
- 使用 bpftool 和 bpftrace 调试 eBPF 程序
- 诊断常见的运行时问题（事件丢失、性能问题等）
- 使用 pprof 和 Pyroscope 进行性能分析
- 检测和定位内存泄漏

### 1.2 调试工具概览

| 工具 | 用途 | 适用场景 |
|------|------|----------|
| Delve | Go 程序调试器 | 用户态代码断点调试 |
| Logger | Tracee 日志系统 | 运行时问题追踪 |
| bpftool | eBPF 程序管理 | 查看已加载的 BPF 程序和 Maps |
| bpftrace | eBPF 跟踪工具 | 辅助调试和验证 |
| pprof | Go 性能分析 | CPU/内存性能分析 |
| Pyroscope | 持续性能分析 | 长期性能监控 |
| race detector | Go 竞态检测 | 并发问题定位 |

---

## 2. 开发环境搭建

### 2.1 安装调试工具

```bash
# 安装 Delve
go install github.com/go-delve/delve/cmd/dlv@latest

# 安装 bpftool (Ubuntu/Debian)
sudo apt-get install linux-tools-common linux-tools-generic

# 安装 bpftrace
sudo apt-get install bpftrace

# 验证安装
dlv version
bpftool version
bpftrace --version
```

### 2.2 编译 Debug 版本

Tracee Makefile 提供了 DEBUG 标志用于构建带调试符号的二进制文件：

```bash
# 构建带调试符号的 Tracee（不剥离符号表）
DEBUG=1 make tracee

# 验证调试符号
file ./dist/tracee
# 输出应包含 "with debug_info, not stripped"
```

**关键 Makefile 变量**：

```makefile
# Makefile 第 168-177 行
DEBUG ?= 0

ifeq ($(DEBUG),1)
    GO_DEBUG_FLAG =
else
    GO_DEBUG_FLAG = -w  # -w 剥离 DWARF 调试信息
endif
```

### 2.3 生成 compile_commands.json

为 IDE 提供 eBPF C 代码的智能提示：

```bash
# 生成 compile_commands.json（用于 clangd 等 LSP）
make bear
```

---

## 3. 用户态代码调试

### 3.1 使用 Delve 调试

#### 基本调试命令

```bash
# 启动调试会话（需要 root 权限运行 Tracee）
sudo dlv exec ./dist/tracee -- --events open,execve

# 或者附加到正在运行的进程
sudo dlv attach <PID>
```

#### 常用 Delve 命令

```
# 断点管理
(dlv) break pkg/ebpf/tracee.go:100    # 设置断点
(dlv) break main.main                  # 函数入口断点
(dlv) breakpoints                      # 列出所有断点
(dlv) clear 1                          # 删除断点

# 执行控制
(dlv) continue                         # 继续执行
(dlv) next                             # 单步（不进入函数）
(dlv) step                             # 单步（进入函数）
(dlv) stepout                          # 执行到函数返回

# 查看变量
(dlv) print varName                    # 打印变量
(dlv) locals                           # 显示局部变量
(dlv) args                             # 显示函数参数

# 堆栈查看
(dlv) stack                            # 显示调用栈
(dlv) goroutines                       # 列出所有 goroutine
(dlv) goroutine <id>                   # 切换到指定 goroutine
```

#### 调试示例：跟踪事件处理流程

```bash
# 在事件处理入口设置断点
sudo dlv exec ./dist/tracee -- --events execve

(dlv) break pkg/ebpf/processor.go:handleEvents
(dlv) continue

# 当断点触发时，查看事件数据
(dlv) locals
(dlv) print event
```

### 3.2 日志系统配置

Tracee 使用基于 zap 的日志系统，支持多种配置选项。

#### 日志级别

日志系统定义在 `common/logger/logger.go` 中：

```go
const (
    DebugLevel  Level = zap.DebugLevel   // -1
    InfoLevel   Level = zap.InfoLevel    // 0 (默认)
    WarnLevel   Level = zap.WarnLevel    // 1
    ErrorLevel  Level = zap.ErrorLevel   // 2
    FatalLevel  Level = zap.FatalLevel   // 5
)
```

#### 命令行日志配置

```bash
# 设置日志级别
sudo ./dist/tracee --log debug

# 输出到文件
sudo ./dist/tracee --log debug --log file:/tmp/tracee.log

# 日志聚合（减少重复日志输出）
sudo ./dist/tracee --log debug --log aggregate:5s

# 日志过滤 - 只显示包含特定内容的日志
sudo ./dist/tracee --log filter:'msg=event;pkg=ebpf'

# 日志过滤 - 排除特定日志
sudo ./dist/tracee --log filter-out:'pkg=container'

# 过滤 libbpf 日志
sudo ./dist/tracee --log filter:libbpf
```

#### YAML 配置文件方式

```yaml
# config.yaml
log:
  level: debug
  file: "/tmp/tracee.log"
  aggregate:
    enabled: true
    flush-interval: "10s"
  filters:
    msg:
      - "event"
      - "error"
    pkg:
      - "ebpf"
    level:
      - "error"
      - "warn"
```

#### 代码中使用日志

```go
import "github.com/aquasecurity/tracee/common/logger"

// 基本用法
logger.Debugw("Processing event", "eventID", event.EventID, "pid", event.ProcessID)
logger.Infow("Tracee started", "version", version)
logger.Warnw("Event lost", "count", lostCount)
logger.Errorw("Failed to decode event", "error", err)

// 动态调整日志级别
logger.SetLevel(logger.DebugLevel)
```

### 3.3 常用调试技巧

#### 使用 Go 的 race detector

```bash
# 构建并运行测试时启用竞态检测
make test-unit  # 默认启用 -race 标志

# 手动运行带 race 检测的测试
go test -race -v ./pkg/ebpf/...
```

#### 条件断点

```bash
# 只在特定条件下触发断点
(dlv) break pkg/ebpf/processor.go:100
(dlv) condition 1 event.EventID == 59  # execve 的事件 ID
```

---

## 4. eBPF 程序调试

### 4.1 使用 bpftool 查看 eBPF 程序

#### 列出已加载的 BPF 程序

```bash
# 列出所有 BPF 程序
sudo bpftool prog list

# 输出示例：
# 123: raw_tracepoint  name tracepoint__raw  tag abc123...
#      loaded_at 2024-01-15T10:30:00+0000  uid 0
#      xlated 1024B  jited 768B  memlock 4096B
```

#### 查看程序详情

```bash
# 查看特定程序的详细信息
sudo bpftool prog show id 123

# 查看程序的指令（用于验证编译结果）
sudo bpftool prog dump xlated id 123

# 查看 JIT 编译后的机器码
sudo bpftool prog dump jited id 123
```

### 4.2 查看和操作 BPF Maps

Tracee 使用多种 BPF Maps 存储状态数据（定义在 `pkg/ebpf/c/maps.h`）：

```bash
# 列出所有 BPF Maps
sudo bpftool map list

# 查看特定 Map 的内容
sudo bpftool map dump id <map_id>

# 查看 Map 的键值对
sudo bpftool map lookup id <map_id> key <hex_key>

# 常用 Tracee Maps：
# - task_info_map: 任务信息
# - config_map: 配置参数
# - events: Perf Buffer 事件队列
# - logs_count: BPF 日志计数
```

#### 使用 bpftool 调试 Maps 示例

```bash
# 查看 config_map 的内容
sudo bpftool map dump name config_map

# 查看 task_info_map 的条目数
sudo bpftool map show name task_info_map

# 查看特定进程的任务信息（假设知道 tid）
sudo bpftool map lookup name task_info_map key 0x01 0x00 0x00 0x00
```

### 4.3 使用 bpftrace 辅助调试

bpftrace 可以帮助验证系统调用和事件触发情况：

```bash
# 跟踪所有 execve 系统调用
sudo bpftrace -e 'tracepoint:syscalls:sys_enter_execve {
    printf("execve: pid=%d comm=%s\n", pid, comm);
}'

# 跟踪 Tracee 正在监控的 kprobe
sudo bpftrace -e 'kprobe:security_bprm_check {
    printf("security_bprm_check called: pid=%d\n", pid);
}'

# 验证 perf buffer 是否有数据
sudo bpftrace -e 'tracepoint:bpf:bpf_trace_printk {
    printf("%s\n", str(args->buf));
}'
```

### 4.4 eBPF 程序的日志输出

Tracee 在 eBPF 层实现了日志系统（定义在 `pkg/ebpf/c/common/logging.h`）：

```c
// eBPF 程序中的日志调用
tracee_log(ctx, BPF_LOG_LEVEL_ERROR, BPF_LOG_ID_MAP_LOOKUP_ELEM, ret);
```

日志在用户空间通过 `processBPFLogs` 函数处理（`pkg/ebpf/bpf_log.go`）：

```go
// BPF 日志类型
const (
    BPFLogIDMapLookupElem  // Map 查找失败
    BPFLogIDMapUpdateElem  // Map 更新失败
    BPFLogIDMapDeleteElem  // Map 删除失败
    BPFLogIDTailCall       // Tail call 失败
    BPFLogIDMemRead        // 内存读取失败
    // ...
)
```

**查看 BPF 日志**：

```bash
# 启用 debug 级别以查看 BPF 日志
sudo ./dist/tracee --log debug 2>&1 | grep "BPF_LOG"
```

### 4.5 查看已附加的 Kprobes

```bash
# 查看当前附加的 kprobes
cat /sys/kernel/debug/kprobes/list

# 输出示例：
# ffffffff81234567 k security_bprm_check+0x0    [DISABLED]
# ffffffff81234568 r security_bprm_check+0x0    [DISABLED]
```

---

## 5. 常见问题排查

### 5.1 程序加载失败

#### 症状

```
error: failed to load BPF program: ...
```

#### 排查步骤

1. **检查内核版本兼容性**：

```bash
# 查看内核版本
uname -r

# Tracee 要求内核 >= 5.4（推荐 5.8+）
```

2. **检查 BTF 支持**：

```bash
# 确认内核支持 BTF
ls /sys/kernel/btf/vmlinux

# 如果不存在，可能需要使用 BTFHub
BTFHUB=1 STATIC=1 make tracee
```

3. **检查权限**：

```bash
# Tracee 需要 root 权限或特定 capabilities
sudo ./dist/tracee

# 或使用 capabilities
sudo setcap cap_sys_admin,cap_sys_ptrace,cap_sys_resource,cap_net_admin+ep ./dist/tracee
```

4. **查看 verifier 错误**：

```bash
# BPF verifier 日志
sudo ./dist/tracee --log debug 2>&1 | grep -i "verifier"
```

### 5.2 事件丢失

#### 症状

日志中出现 "lost events" 或 Prometheus 指标 `lostevents_total` 增加。

#### 排查步骤

1. **检查丢失计数**：

```bash
# 通过 metrics 接口查看
curl -s http://localhost:3366/metrics | grep lost
```

2. **调整 Perf Buffer 大小**：

```bash
# 增加 perf buffer 大小（默认 1024 页）
sudo ./dist/tracee --perf-buffer-size 4096
```

3. **减少监控事件数量**：

```bash
# 只监控必要的事件
sudo ./dist/tracee --events execve,openat,connect
```

4. **检查统计信息**：

Stats 结构体（`pkg/metrics/stats.go`）跟踪多种丢失计数：

```go
type Stats struct {
    LostEvCount      *counter.Counter  // 主事件丢失
    LostWrCount      *counter.Counter  // 写捕获丢失
    LostNtCapCount   *counter.Counter  // 网络捕获丢失
    LostBPFLogsCount *counter.Counter  // BPF 日志丢失
}
```

### 5.3 性能问题定位

#### 症状

- CPU 使用率过高
- 事件处理延迟
- 系统响应变慢

#### 排查步骤

1. **启用性能指标**：

```bash
# 编译时启用 metrics
METRICS=1 make tracee

# 运行时启用
sudo ./dist/tracee --server metrics
```

2. **查看性能指标**：

```bash
# 通过 HTTP 接口
curl http://localhost:3366/metrics

# 关注指标：
# - tracee_ebpf_events_total
# - tracee_ebpf_lostevents_total
# - tracee_ebpf_bpf_perf_event_submit_failures
```

3. **使用 pprof 分析**：

```bash
# 启用 pprof
sudo ./dist/tracee --server pprof

# 收集 CPU profile
go tool pprof http://localhost:3366/debug/pprof/profile?seconds=30

# 收集内存 profile
go tool pprof http://localhost:3366/debug/pprof/heap
```

---

## 6. 性能分析工具

### 6.1 使用 pprof

Tracee 内置 pprof 支持（`pkg/server/http/server.go`）：

```bash
# 启动 Tracee 时启用 pprof
sudo ./dist/tracee --server pprof

# 可用的 pprof endpoints：
# /debug/pprof/         - 索引页面
# /debug/pprof/profile  - CPU profile
# /debug/pprof/heap     - 内存 profile
# /debug/pprof/allocs   - 内存分配 profile
# /debug/pprof/block    - 阻塞 profile
# /debug/pprof/goroutine - Goroutine 堆栈
```

#### 生成火焰图

```bash
# 安装 go-torch 或使用 pprof 自带功能
go tool pprof -http=:8080 http://localhost:3366/debug/pprof/profile?seconds=30

# 在浏览器中打开 http://localhost:8080 查看火焰图
```

### 6.2 使用 Pyroscope 持续性能分析

```bash
# 启动 Tracee 时启用 Pyroscope
sudo ./dist/tracee --server pyroscope --server pprof

# 启动性能仪表板（包含 Grafana + Pyroscope）
make -f builder/Makefile.performance dashboard-start

# 访问仪表板
# - Grafana: http://localhost:3000/
# - Pyroscope: http://localhost:4040/?query=tracee.cpu

# 停止仪表板
make -f builder/Makefile.performance dashboard-stop
```

### 6.3 性能基准测试

```bash
# 运行性能测试
make test-performance

# 运行 signatures 基准测试
cd pkg/signatures/benchmark
make
```

---

## 7. 内存泄漏检测

### 7.1 使用 Go 内置工具

```bash
# 启用 pprof
sudo ./dist/tracee --server pprof

# 收集内存 profile
go tool pprof http://localhost:3366/debug/pprof/heap

# 在 pprof 交互模式中
(pprof) top 10           # 查看内存使用最多的函数
(pprof) list funcName    # 查看特定函数的详细信息
(pprof) web              # 生成调用图（需要 graphviz）
```

### 7.2 使用 goleak 检测 Goroutine 泄漏

Tracee 测试中使用 goleak 检测 goroutine 泄漏（参见 `tests/integration/dependencies_test.go`）：

```go
import "go.uber.org/goleak"

func TestXxx(t *testing.T) {
    defer goleak.VerifyNone(t)
    // 测试代码
}
```

### 7.3 监控运行时内存

```bash
# 通过 runtime 指标
curl -s http://localhost:3366/debug/pprof/heap?debug=1 | head -50

# 使用 expvar（如果启用）
curl -s http://localhost:3366/debug/vars | jq '.memstats'
```

---

## 8. 动手练习

### 练习 1：调试事件处理流程

**目标**：使用 Delve 跟踪一个 execve 事件从 eBPF 到用户空间的完整流程。

**步骤**：

1. 构建 debug 版本：
```bash
DEBUG=1 make tracee
```

2. 启动调试会话：
```bash
sudo dlv exec ./dist/tracee -- --events execve
```

3. 设置断点：
```
(dlv) break pkg/ebpf/processor.go:handleEvents
(dlv) continue
```

4. 在另一个终端触发事件：
```bash
ls /tmp
```

5. 观察事件处理：
```
(dlv) print event
(dlv) stack
```

### 练习 2：分析 BPF Maps

**目标**：使用 bpftool 查看 Tracee 运行时的 BPF Maps 状态。

**步骤**：

1. 启动 Tracee：
```bash
sudo ./dist/tracee --events execve &
```

2. 列出 BPF Maps：
```bash
sudo bpftool map list | grep -E "task_info|config"
```

3. 查看 config_map 内容：
```bash
sudo bpftool map dump name config_map
```

4. 执行一些命令触发事件：
```bash
for i in {1..10}; do ls /tmp > /dev/null; done
```

5. 检查 task_info_map 的条目：
```bash
sudo bpftool map show name task_info_map
```

### 练习 3：性能分析

**目标**：使用 pprof 分析 Tracee 的 CPU 使用情况。

**步骤**：

1. 启动 Tracee 并启用 pprof：
```bash
sudo ./dist/tracee --server pprof &
```

2. 生成负载：
```bash
# 在另一个终端运行
while true; do find /usr -name "*.so" > /dev/null 2>&1; done &
```

3. 收集 CPU profile：
```bash
go tool pprof -http=:8080 http://localhost:3366/debug/pprof/profile?seconds=30
```

4. 在浏览器中查看火焰图，分析热点函数。

5. 清理：
```bash
# 停止负载生成
kill %1
# 停止 Tracee
sudo pkill tracee
```

### 练习 4：日志调试

**目标**：使用日志系统定位特定事件的处理过程。

**步骤**：

1. 启动带详细日志的 Tracee：
```bash
sudo ./dist/tracee --events openat --log debug --log file:/tmp/tracee.log
```

2. 在另一个终端触发 openat 事件：
```bash
cat /etc/passwd
```

3. 分析日志：
```bash
# 查看事件处理相关日志
grep -i "openat\|decode\|process" /tmp/tracee.log | tail -20

# 查看性能相关信息
grep -i "goroutine\|channel" /tmp/tracee.log
```

4. 使用日志过滤：
```bash
# 只查看 ebpf 包的日志
sudo ./dist/tracee --events openat --log debug --log filter:'pkg=ebpf'
```

---

## 总结

本指南涵盖了 Tracee 调试的主要方面：

| 调试类型 | 主要工具 | 关键命令/配置 |
|----------|----------|---------------|
| 用户态代码 | Delve | `dlv exec`, `dlv attach` |
| 日志分析 | Logger | `--log debug`, `--log filter:...` |
| eBPF 程序 | bpftool | `bpftool prog list`, `bpftool map dump` |
| eBPF 辅助 | bpftrace | 自定义跟踪脚本 |
| 性能分析 | pprof | `--server pprof`, `go tool pprof` |
| 持续监控 | Pyroscope | `--server pyroscope`, 性能仪表板 |
| 内存检测 | pprof/goleak | heap profile, `goleak.VerifyNone` |

**调试最佳实践**：

1. **先启用日志**：大多数问题可以通过详细日志定位
2. **使用 debug 构建**：`DEBUG=1 make tracee` 保留调试符号
3. **监控指标**：关注 metrics 中的 lost events 和错误计数
4. **逐步缩小范围**：从日志到断点，从整体到局部
5. **保存现场**：问题发生时收集 pprof 数据和 BPF Maps 状态

---

## 参考资源

- [Delve 官方文档](https://github.com/go-delve/delve/tree/master/Documentation)
- [bpftool 手册](https://man7.org/linux/man-pages/man8/bpftool.8.html)
- [bpftrace 参考指南](https://github.com/iovisor/bpftrace/blob/master/docs/reference_guide.md)
- [Go pprof 文档](https://pkg.go.dev/net/http/pprof)
- [Tracee 性能分析文档](/docs/contributing/performance.md)
- [Tracee 日志配置](/docs/docs/outputs/logging.md)
