# Tracee 输出管道架构详解

**学习时长**: 2-3 天
**难度级别**: ⭐⭐⭐
**前置知识**: Go 语言基础、了解 Tracee 事件结构

---

## 目录

1. [概述与学习目标](#1-概述与学习目标)
2. [输出管道架构图](#2-输出管道架构图)
3. [事件序列化](#3-事件序列化)
4. [输出目标](#4-输出目标)
5. [Printer 接口详解](#5-printer-接口详解)
6. [多输出目标支持](#6-多输出目标支持)
7. [Metrics 输出 (Prometheus)](#7-metrics-输出-prometheus)
8. [自定义输出插件开发](#8-自定义输出插件开发)
9. [与外部系统集成](#9-与外部系统集成)
10. [动手练习](#10-动手练习)
11. [核心代码走读](#11-核心代码走读)

---

## 1. 概述与学习目标

### 1.1 什么是输出管道

Tracee 的输出管道是将 eBPF 捕获的内核事件传递给用户的核心机制。它负责：

- **事件序列化**: 将 `trace.Event` 结构体转换为不同格式（JSON、Table、GELF 等）
- **输出路由**: 将事件分发到不同的输出目标（标准输出、文件、网络、gRPC）
- **事件流分发**: 支持多个订阅者同时消费事件流
- **指标收集**: 通过 Prometheus 暴露运行时指标

### 1.2 学习目标

完成本教程后，你将能够：

1. 理解 Tracee 输出管道的整体架构
2. 掌握不同格式的事件序列化机制
3. 了解各种输出目标的实现原理
4. 实现自定义的 Printer 插件
5. 配置 Prometheus 指标输出
6. 将 Tracee 与 Loki、Grafana 等外部系统集成

### 1.3 核心源码文件

| 文件路径 | 功能描述 |
|---------|---------|
| `pkg/cmd/printer/printer.go` | Printer 接口和各种格式实现 |
| `pkg/cmd/printer/broadcast.go` | 多目标广播器 |
| `pkg/server/grpc/server.go` | gRPC 服务实现 |
| `pkg/server/grpc/tracee.go` | 事件流服务 |
| `pkg/server/http/server.go` | HTTP/Metrics 服务 |
| `pkg/metrics/stats.go` | 统计指标定义 |
| `pkg/streams/streams.go` | 事件流分发管理 |
| `types/trace/trace.go` | 事件数据结构 |

---

## 2. 输出管道架构图

### 2.1 整体架构

```
                              ┌─────────────────────────────────────────────────────────────┐
                              │                    Tracee 输出管道架构                        │
                              └─────────────────────────────────────────────────────────────┘

    ┌──────────��───┐
    │  eBPF 探针    │
    │  (内核态)     │
    └──────┬───────┘
           │ perf buffer / ring buffer
           ▼
    ┌──────────────┐
    │   Tracee     │
    │  (用户态)     │
    │  事件解码     │
    └──────┬───────┘
           │ trace.Event
           ▼
    ┌──────────────────────────────────────────────────────────────────────────────────┐
    │                              StreamsManager (事件流分发)                           │
    │  ┌─────────────────────────────────────────────────────────────────────────────┐ │
    │  │  Stream 1         Stream 2         Stream 3         Stream N               │ │
    │  │  (Policy A)       (Policy B)       (Policy C)       (All Policies)         │ │
    │  └─────────────────────────────────────────────────────────────────────────────┘ │
    └───────────┬─────────────────┬─────────────────┬─────────────────┬────────────────┘
                │                 │                 │                 │
                ▼                 ▼                 ▼                 ▼
    ┌───────────────────────────────────────────────────────────────────────────────────┐
    │                               Broadcast (广播器)                                    │
    │  ┌─────────────────────────────────────────────────────────────────────────────┐  │
    │  │                         EventPrinter 接口实现                                 │  │
    │  │                                                                              │  │
    │  │  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐            │  │
    │  │  │  Table      │ │  JSON       │ │  GoTemplate │ │  Ignore     │            │  │
    │  │  │  Printer    │ │  Printer    │ │  Printer    │ │  Printer    │            │  │
    │  │  └──────┬──────┘ └──────┬──────┘ └──────┬──────┘ └─────────────┘            │  │
    │  │         │               │               │                                    │  │
    │  │  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐                            │  │
    │  │  │  Forward    │ │  Webhook    │ │  gRPC       │                            │  │
    │  │  │  Printer    │ │  Printer    │ │  Stream     │                            │  │
    │  │  └──────┬──────┘ └──────┬──────┘ └──────┬──────┘                            │  │
    │  └─────────┼───────────────┼───────────────┼────────────────────────────────────┘  │
    └────────────┼───────────────┼───────────────┼──────────────────────────────────────┘
                 │               │               │
                 ▼               ▼               ▼
    ┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
    │   标准输出/文件   │ │   HTTP Webhook  │ │   gRPC Client   │
    │   Fluent Forward │ │   SIEM 系统      │ │   traceectl     │
    └─────────────────┘ └─────────────────┘ └─────────────────┘


    ┌──────────────────────────────────────────────────────────────────────────────────┐
    │                              Metrics 输出 (独立路径)                              │
    │                                                                                  │
    │  ┌─────────────┐      ┌─────────────────┐      ┌─────────────────────────────┐  │
    │  │   Stats     │ ───▶ │  Prometheus     │ ───▶ │  /metrics endpoint          │  │
    │  │   收集器     │      │  Registry       │      │  (HTTP Server)              │  │
    │  └─────────────┘      └─────────────────┘      └─────────────────────────────┘  │
    │                                                          │                       │
    │                                                          ▼                       │
    │                                               ┌─────────────────────┐            │
    │                                               │  Prometheus Server  │            │
    │                                               │  Grafana Dashboard  │            │
    │                                               └─────────────────────┘            │
    └──────────────────────────────────────────────────────────────────────────────────┘
```

### 2.2 数据流向

```
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                                事件数据流向详解                                          │
└─────────────────────────────────────────────────────────────────────────────────────────┘

  步骤 1: 事件生成
  ─────────────────
  eBPF 程序捕获系统调用/内核事件
           │
           ▼
  ┌──────────────────────────────────────────┐
  │  struct event_data_t {                   │
  │      u64 timestamp;                      │
  │      u32 pid, tid;                       │
  │      char comm[16];                      │
  │      // ... 更多字段                     │
  │  }                                       │
  └──────────────────────────────────────────┘
           │
           ▼
  步骤 2: 用户态解码
  ─────────────────
  Tracee 从 perf buffer 读取并解码
           │
           ▼
  ┌──────────────────────────────────────────┐
  │  type Event struct {                     │
  │      Timestamp   int                     │
  │      ProcessID   int                     │
  │      ProcessName string                  │
  │      EventName   string                  │
  │      Args        []Argument              │
  │      // ... 更多字段                     │
  │  }                                       │
  │  (types/trace/trace.go)                  │
  └──────────────────────────────────────────┘
           │
           ▼
  步骤 3: 事件分发
  ─────────────────
  StreamsManager 根据策略分发事件
           │
           ├─────────────────┬─────────────────┐
           ▼                 ▼                 ▼
  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
  │  Stream A   │    │  Stream B   │    │  Stream C   │
  │  (订阅者 1)  │    │  (订阅者 2)  │    │  (订阅者 3)  │
  └─────────────┘    └─────────────┘    └─────────────┘
           │
           ▼
  步骤 4: 序列化输出
  ─────────────────
  Printer 将事件转换为目标格式
           │
           ├──────────────┬──────────────┬──────────────┐
           ▼              ▼              ▼              ▼
  ┌────────────┐  ┌────────────┐  ┌────────────┐  ┌────────────┐
  │   JSON     │  │   Table    │  │  Template  │  │   gRPC     │
  │ {"event":} │  │ TIME PID.. │  │  自定义格式  │  │  protobuf  │
  └────────────┘  └────────────┘  └────────────┘  └────────────┘
```

---

## 3. 事件序列化

### 3.1 trace.Event 核心结构

事件的数据结构定义在 `types/trace/trace.go` 中：

```go
// Event 是 eBPF 事件处理的结果，用于传递给 tracee-rules
type Event struct {
    Timestamp             int          `json:"timestamp"`
    ThreadStartTime       int          `json:"threadStartTime"`
    ProcessorID           int          `json:"processorId"`
    ProcessID             int          `json:"processId"`
    CgroupID              uint         `json:"cgroupId"`
    ThreadID              int          `json:"threadId"`
    ParentProcessID       int          `json:"parentProcessId"`
    HostProcessID         int          `json:"hostProcessId"`
    HostThreadID          int          `json:"hostThreadId"`
    HostParentProcessID   int          `json:"hostParentProcessId"`
    UserID                int          `json:"userId"`
    MountNS               int          `json:"mountNamespace"`
    PIDNS                 int          `json:"pidNamespace"`
    ProcessName           string       `json:"processName"`
    Executable            File         `json:"executable"`
    HostName              string       `json:"hostName"`
    ContainerID           string       `json:"containerId"`
    Container             Container    `json:"container,omitempty"`
    Kubernetes            Kubernetes   `json:"kubernetes,omitempty"`
    EventID               int          `json:"eventId,string"`
    EventName             string       `json:"eventName"`
    MatchedPolicies       []string     `json:"matchedPolicies,omitempty"`
    ArgsNum               int          `json:"argsNum"`
    ReturnValue           int          `json:"returnValue"`
    Syscall               string       `json:"syscall"`
    StackAddresses        []uint64     `json:"stackAddresses"`
    Args                  []Argument   `json:"args"`
    Metadata              *Metadata    `json:"metadata,omitempty"`
}

// Argument 保存单个参数的信息
type Argument struct {
    ArgMeta
    Value interface{} `json:"value"`
}

// ArgMeta 描述参数的元数据
type ArgMeta struct {
    Name string `json:"name"`
    Type string `json:"type"`
}
```

### 3.2 JSON 格式

JSON 格式是最常用的输出格式，适合日志分析和数据处理。

**实现代码** (`pkg/cmd/printer/printer.go`):

```go
type jsonEventPrinter struct {
    out io.WriteCloser
}

func (p jsonEventPrinter) Init() error { return nil }

func (p jsonEventPrinter) Preamble() {}

func (p jsonEventPrinter) Print(event trace.Event) {
    eBytes, err := json.Marshal(event)
    if err != nil {
        logger.Errorw("Error marshaling event to json", "error", err)
    }
    fmt.Fprintln(p.out, string(eBytes))
}

func (p jsonEventPrinter) Epilogue(stats metrics.Stats) {}

func (p jsonEventPrinter) Close() {}
```

**输出示例**:

```json
{
  "timestamp": 1705847256123456789,
  "processId": 1234,
  "threadId": 1234,
  "parentProcessId": 1,
  "hostProcessId": 5678,
  "userId": 0,
  "processName": "bash",
  "eventId": "59",
  "eventName": "execve",
  "returnValue": 0,
  "args": [
    {"name": "pathname", "type": "const char*", "value": "/bin/ls"},
    {"name": "argv", "type": "const char*const*", "value": ["ls", "-la"]},
    {"name": "envp", "type": "const char*const*", "value": ["PATH=/usr/bin"]}
  ]
}
```

### 3.3 Table 格式

Table 格式提供人类可读的表格输出，适合终端调试。

**实现代码**:

```go
type tableEventPrinter struct {
    out           io.WriteCloser
    verbose       bool
    containerMode config.ContainerMode
    relativeTS    bool
}

func (p tableEventPrinter) Preamble() {
    if p.verbose {
        switch p.containerMode {
        case config.ContainerModeDisabled:
            fmt.Fprintf(p.out,
                "%-16s %-17s %-13s %-12s %-12s %-6s %-16s %-7s %-7s %-7s %-16s %-25s %s",
                "TIME", "UTS_NAME", "CONTAINER_ID", "MNT_NS", "PID_NS",
                "UID", "COMM", "PID", "TID", "PPID", "RET", "EVENT", "ARGS",
            )
        // ... 其他模式
        }
    }
    fmt.Fprintln(p.out)
}

func (p tableEventPrinter) Print(event trace.Event) {
    ut := time.Unix(0, int64(event.Timestamp))
    timestamp := fmt.Sprintf("%02d:%02d:%02d:%06d",
        ut.Hour(), ut.Minute(), ut.Second(), ut.Nanosecond()/1000)

    // 格式化输出
    fmt.Fprintf(p.out,
        "%-16s %-6d %-16s %-7d %-7d %-16d %-25s ",
        timestamp,
        event.UserID,
        event.ProcessName,
        event.ProcessID,
        event.ThreadID,
        event.ReturnValue,
        event.EventName,
    )

    // 输出参数
    for i, arg := range event.Args {
        if i == 0 {
            fmt.Fprintf(p.out, "%s: %v", arg.Name, arg.Value)
        } else {
            fmt.Fprintf(p.out, ", %s: %v", arg.Name, arg.Value)
        }
    }
    fmt.Fprintln(p.out)
}
```

**输出示例**:

```
TIME             UID    COMM             PID     TID     RET              EVENT                     ARGS
12:34:56:123456  0      bash             1234    1234    0                execve                    pathname: /bin/ls, argv: [ls -la]
12:34:56:234567  1000   python3          2345    2345    3                openat                    dirfd: -100, pathname: /etc/passwd
```

### 3.4 自定义模板 (GoTemplate)

使用 Go 模板引擎支持高度自定义的输出格式。

**实现代码**:

```go
type templateEventPrinter struct {
    out          io.WriteCloser
    templatePath string
    templateObj  **template.Template
}

func (p *templateEventPrinter) Init() error {
    tmplPath := p.templatePath
    if tmplPath == "" {
        return errfmt.Errorf("please specify a gotemplate for event-based output")
    }

    // 加载模板，支持 sprig 函数库
    tmpl, err := template.New(filepath.Base(tmplPath)).
        Funcs(sprig.TxtFuncMap()).
        ParseFiles(tmplPath)
    if err != nil {
        return errfmt.WrapError(err)
    }
    p.templateObj = &tmpl
    return nil
}

func (p templateEventPrinter) Print(event trace.Event) {
    if p.templateObj != nil {
        err := (*p.templateObj).Execute(p.out, event)
        if err != nil {
            logger.Errorw("Error executing template", "error", err)
        }
    }
}
```

**自定义模板示例** (GELF 格式):

```go
// gelf.tmpl - Graylog Extended Log Format
{
  "version": "1.1",
  "host": "{{ .HostName }}",
  "short_message": "{{ .EventName }}",
  "timestamp": {{ div .Timestamp 1000000000 }}.{{ mod .Timestamp 1000000000 }},
  "level": 6,
  "_process_name": "{{ .ProcessName }}",
  "_process_id": {{ .ProcessID }},
  "_user_id": {{ .UserID }},
  "_container_id": "{{ .Container.ID }}",
  "_event_id": {{ .EventID }}
}
```

**Syslog 格式模板**:

```go
// syslog.tmpl
<14>{{ now | date "Jan 02 15:04:05" }} {{ .HostName }} tracee[{{ .ProcessID }}]: event={{ .EventName }} pid={{ .ProcessID }} user={{ .UserID }}{{ range .Args }} {{ .Name }}={{ .Value }}{{ end }}
```

### 3.5 gRPC Protobuf 序列化

gRPC 使用 Protocol Buffers 进行高效的二进制序列化。

**事件转换代码** (`pkg/server/grpc/tracee.go`):

```go
func convertTraceeEventToProto(e trace.Event) (*pb.Event, error) {
    process := getProcess(e)
    container := getContainer(e)
    k8s := getK8s(e)
    idExternal := getExternalID(e)

    var eventWorkload *pb.Workload
    if process != nil || container != nil || k8s != nil {
        eventWorkload = &pb.Workload{
            Process:   process,
            Container: container,
            K8S:       k8s,
        }
    }

    eventData, err := getEventData(e)
    if err != nil {
        return nil, err
    }

    event := &pb.Event{
        Id:   idExternal,
        Name: sanitizeStringForProtobuf(e.EventName),
        Policies: &pb.Policies{
            Matched: sanitizeStringArrayForProtobuf(e.MatchedPolicies),
        },
        Workload:    eventWorkload,
        Data:        eventData,
        Threat:      threat,
        TriggeredBy: triggerEvent,
    }

    if e.Timestamp != 0 {
        event.Timestamp = timestamppb.New(time.Unix(0, int64(e.Timestamp)))
    }

    return event, nil
}
```

---

## 4. 输出目标

### 4.1 标准输出/文件

最基本的输出方式，将事件写入 stdout 或文件。

**配置结构** (`pkg/config/config.go`):

```go
type PrinterConfig struct {
    Kind          string           // 输出类型: json, table, table-verbose, ignore
    OutPath       string           // 输出路径
    OutFile       io.WriteCloser   // 输出文件句柄
    ContainerMode ContainerMode    // 容器模式
}
```

**使用方式**:

```bash
# 输出到标准输出 (JSON 格式)
tracee --output json

# 输出到文件
tracee --output json:/var/log/tracee/events.json

# 表格格式输出
tracee --output table

# 详细表格格式
tracee --output table-verbose
```

### 4.2 网络输出 - Forward (Fluent)

使用 Fluent Forward 协议发送事件，兼容 Fluentd/Fluent Bit。

**实现代码**:

```go
type forwardEventPrinter struct {
    outPath string
    url     *url.URL
    client  *forward.Client
    tag     string `default:"tracee"`
}

func (p *forwardEventPrinter) Init() error {
    u, err := url.Parse(p.outPath)
    if err != nil {
        return fmt.Errorf("unable to parse URL %q: %w", p.url, err)
    }
    p.url = u

    parameters, _ := url.ParseQuery(p.url.RawQuery)
    p.tag = getParameterValue(parameters, "tag", "tracee")

    // 解析连接参数
    requireAckString := getParameterValue(parameters, "requireAck", "false")
    requireAck, _ := strconv.ParseBool(requireAckString)

    timeoutValueString := getParameterValue(parameters, "connectionTimeout", "10s")
    connectionTimeout, _ := time.ParseDuration(timeoutValueString)

    // 创建 Fluent Forward 客户端
    p.client = forward.New(forward.ConnectionOptions{
        Factory: &forward.ConnFactory{
            Network: "tcp",
            Address: p.url.Host,
        },
        RequireAck:        requireAck,
        ConnectionTimeout: connectionTimeout,
    })

    return p.client.Connect()
}

func (p *forwardEventPrinter) Print(event trace.Event) {
    eBytes, err := json.Marshal(event)
    if err != nil {
        logger.Errorw("Error marshaling event to json", "error", err)
        return
    }

    record := map[string]interface{}{
        "event": string(eBytes),
    }

    err = p.client.SendMessage(p.tag, record)
    if err != nil {
        // 重试逻辑
        for attempts := 0; attempts < 5; attempts++ {
            if err = p.client.Reconnect(); err == nil {
                if err = p.client.SendMessage(p.tag, record); err == nil {
                    break
                }
            }
        }
    }
}
```

**使用方式**:

```bash
# 发送到 Fluentd
tracee --output forward:tcp://fluentd.example.com:24224?tag=security.tracee

# 带认证
tracee --output forward:tcp://user:pass@fluentd:24224?tag=tracee&requireAck=true
```

### 4.3 网络输出 - Webhook

通过 HTTP POST 发送事件到 Webhook 端点。

**实现代码**:

```go
type webhookEventPrinter struct {
    outPath     string
    url         *url.URL
    timeout     time.Duration
    templateObj *template.Template
    contentType string
}

func (ws *webhookEventPrinter) Init() error {
    u, err := url.Parse(ws.outPath)
    if err != nil {
        return errfmt.Errorf("unable to parse URL %q: %v", ws.outPath, err)
    }
    ws.url = u

    parameters, _ := url.ParseQuery(ws.url.RawQuery)

    // 解析超时
    timeout := getParameterValue(parameters, "timeout", "10s")
    ws.timeout, _ = time.ParseDuration(timeout)

    // 加载自定义模板
    gotemplate := getParameterValue(parameters, "gotemplate", "")
    if gotemplate != "" {
        ws.templateObj, _ = template.New(filepath.Base(gotemplate)).
            Funcs(sprig.TxtFuncMap()).
            ParseFiles(gotemplate)
    }

    ws.contentType = getParameterValue(parameters, "contentType", "application/json")
    return nil
}

func (ws *webhookEventPrinter) Print(event trace.Event) {
    var payload []byte

    if ws.templateObj != nil {
        buf := bytes.Buffer{}
        ws.templateObj.Execute(&buf, event)
        payload = buf.Bytes()
    } else {
        payload, _ = json.Marshal(event)
    }

    client := http.Client{Timeout: ws.timeout}
    req, _ := http.NewRequest(http.MethodPost, ws.url.String(), bytes.NewReader(payload))
    req.Header.Set("Content-Type", ws.contentType)

    resp, err := client.Do(req)
    if err != nil {
        logger.Errorw("Error sending webhook", "error", err)
        return
    }
    defer resp.Body.Close()
}
```

**使用方式**:

```bash
# 基本 Webhook
tracee --output webhook:https://webhook.example.com/tracee

# 带自定义模板
tracee --output webhook:https://slack.com/api/chat.postMessage?gotemplate=/etc/tracee/slack.tmpl&contentType=application/json

# 带超时配置
tracee --output webhook:https://siem.example.com/events?timeout=30s
```

### 4.4 gRPC 流

通过 gRPC 提供实时事件流，供远程客户端订阅。

**服务端实现** (`pkg/server/grpc/tracee.go`):

```go
type TraceeService struct {
    pb.UnimplementedTraceeServiceServer
    tracee *tracee.Tracee
}

func (s *TraceeService) StreamEvents(
    in *pb.StreamEventsRequest,
    grpcStream pb.TraceeService_StreamEventsServer,
) error {
    var stream *streams.Stream
    var err error

    // 根据请求的策略订阅事件流
    if len(in.Policies) == 0 {
        stream = s.tracee.SubscribeAll()
    } else {
        stream, err = s.tracee.Subscribe(in.Policies)
        if err != nil {
            return err
        }
    }
    defer s.tracee.Unsubscribe(stream)

    // 设置字段掩码过滤
    mask := fmutils.NestedMaskFromPaths(in.GetMask().GetPaths())

    // 持续发送事件
    for e := range stream.ReceiveEvents() {
        eventProto, err := convertTraceeEventToProto(e)
        if err != nil {
            logger.Errorw("error can't create event proto: " + err.Error())
            continue
        }

        mask.Filter(eventProto)

        err = grpcStream.Send(&pb.StreamEventsResponse{Event: eventProto})
        if err != nil {
            return err
        }
    }

    return nil
}
```

**gRPC 服务器启动** (`pkg/server/grpc/server.go`):

```go
type Server struct {
    listener   net.Listener
    protocol   string
    listenAddr string
    server     *grpc.Server
}

func (s *Server) Start(ctx context.Context, t *tracee.Tracee, e *engine.Engine) {
    lis, err := net.Listen(s.protocol, s.listenAddr)
    if err != nil {
        logger.Errorw("Failed to start GRPC server", "error", err)
        return
    }
    s.listener = lis

    // 配置 keepalive
    keepaliveParams := keepalive.ServerParameters{
        Time:    5 * time.Second,
        Timeout: 1 * time.Second,
    }

    grpcServer := grpc.NewServer(grpc.KeepaliveParams(keepaliveParams))

    // 注册服务
    pb.RegisterTraceeServiceServer(grpcServer, &TraceeService{tracee: t})
    pb.RegisterDiagnosticServiceServer(grpcServer, &DiagnosticService{tracee: t})
    pb.RegisterDataSourceServiceServer(grpcServer, &DataSourceService{sigEngine: e})

    go grpcServer.Serve(s.listener)

    <-ctx.Done()
    s.server.GracefulStop()
}
```

**客户端使用 (traceectl)**:

```bash
# 连接到 Tracee gRPC 服务
traceectl stream --output json

# 指定策略
traceectl stream --policies policy1,policy2

# 表格格式输出
traceectl stream --output table
```

---

## 5. Printer 接口详解

### 5.1 EventPrinter 接口

所有输出 Printer 都必须实现 `EventPrinter` 接口：

```go
// pkg/cmd/printer/printer.go

type EventPrinter interface {
    // Init 初始化 Printer，在开始输出前调用
    Init() error

    // Preamble 在事件输出开始前打印头部信息（如表格头）
    Preamble()

    // Epilogue 在事件输出结束后打印尾部信息（如统计信息）
    Epilogue(stats metrics.Stats)

    // Print 输出单个事件
    Print(event trace.Event)

    // Close 释放资源
    Close()
}
```

### 5.2 Printer 工厂方法

根据配置创建相应的 Printer 实例：

```go
func New(cfg config.PrinterConfig) (EventPrinter, error) {
    var res EventPrinter
    kind := cfg.Kind

    if cfg.OutFile == nil {
        return res, errfmt.Errorf("out file is not set")
    }

    switch {
    case kind == "ignore":
        res = &ignoreEventPrinter{}
    case kind == "table":
        res = &tableEventPrinter{
            out:           cfg.OutFile,
            verbose:       false,
            containerMode: cfg.ContainerMode,
        }
    case kind == "table-verbose":
        res = &tableEventPrinter{
            out:           cfg.OutFile,
            verbose:       true,
            containerMode: cfg.ContainerMode,
        }
    case kind == "json":
        res = &jsonEventPrinter{
            out: cfg.OutFile,
        }
    case kind == "forward":
        res = &forwardEventPrinter{
            outPath: cfg.OutPath,
        }
    case kind == "webhook":
        res = &webhookEventPrinter{
            outPath: cfg.OutPath,
        }
    case strings.HasPrefix(kind, "gotemplate="):
        res = &templateEventPrinter{
            out:          cfg.OutFile,
            templatePath: strings.Split(kind, "=")[1],
        }
    }

    err := res.Init()
    if err != nil {
        return nil, err
    }
    return res, nil
}
```

### 5.3 Ignore Printer

特殊的 Printer，用于丢弃所有事件（用于性能测试或仅收集指标的场景）：

```go
type ignoreEventPrinter struct{}

func (p *ignoreEventPrinter) Init() error { return nil }
func (p *ignoreEventPrinter) Preamble() {}
func (p *ignoreEventPrinter) Print(event trace.Event) {}  // 不做任何输出
func (p *ignoreEventPrinter) Epilogue(stats metrics.Stats) {}
func (p ignoreEventPrinter) Close() {}
```

---

## 6. 多输出目标支持

### 6.1 Broadcast 广播器

Broadcast 允许将事件同时发送到多个输出目标：

```go
// pkg/cmd/printer/broadcast.go

type Broadcast struct {
    PrinterConfigs []config.PrinterConfig
    printers       []EventPrinter
    wg             *sync.WaitGroup
    eventsChan     []chan trace.Event
    done           chan struct{}
    containerMode  config.ContainerMode
}

func NewBroadcast(
    printerConfigs []config.PrinterConfig,
    containerMode config.ContainerMode,
) (*Broadcast, error) {
    b := &Broadcast{
        PrinterConfigs: printerConfigs,
        containerMode:  containerMode,
    }
    return b, b.Init()
}

func (b *Broadcast) Init() error {
    printers := make([]EventPrinter, 0, len(b.PrinterConfigs))
    wg := &sync.WaitGroup{}

    // 为每个配置创建 Printer
    for _, pConfig := range b.PrinterConfigs {
        pConfig.ContainerMode = b.containerMode
        p, err := New(pConfig)
        if err != nil {
            return err
        }
        printers = append(printers, p)
    }

    // 为每个 Printer 创建独立的事件通道
    eventsChan := make([]chan trace.Event, 0, len(printers))
    done := make(chan struct{})

    for _, printer := range printers {
        eventChan := make(chan trace.Event, 1000)  // 缓冲通道
        eventsChan = append(eventsChan, eventChan)

        wg.Add(1)
        go startPrinter(wg, done, eventChan, printer)
    }

    b.printers = printers
    b.eventsChan = eventsChan
    b.wg = wg
    b.done = done

    return nil
}
```

### 6.2 事件广播

将事件发送到所有订阅的 Printer：

```go
func (b *Broadcast) Print(event trace.Event) {
    for _, c := range b.eventsChan {
        // 阻塞发送 - 如果 Printer 处理慢会导致背压
        c <- event
    }
}

func startPrinter(
    wg *sync.WaitGroup,
    done chan struct{},
    c chan trace.Event,
    p EventPrinter,
) {
    for {
        select {
        case <-done:
            wg.Done()
            return
        case event := <-c:
            p.Print(event)
        }
    }
}
```

### 6.3 生命周期管理

```go
func (b *Broadcast) Preamble() {
    for _, p := range b.printers {
        p.Preamble()
    }
}

func (b *Broadcast) Epilogue(stats metrics.Stats) {
    // 关闭 done 通道，通知所有 goroutine 退出
    close(b.done)
    b.wg.Wait()  // 等待所有 Printer 完成

    for _, p := range b.printers {
        p.Epilogue(stats)
    }
}

func (b *Broadcast) Close() {
    for _, p := range b.printers {
        p.Close()
    }
}

// Active 检查广播器是否有有效的输出目标
func (b *Broadcast) Active() bool {
    kinds := b.Kinds()
    if len(kinds) == 0 || (len(kinds) == 1 && kinds[0] == "ignore") {
        return false
    }
    return true
}
```

### 6.4 使用示例

```bash
# 同时输出到多个目标
tracee \
  --output json:/var/log/tracee/events.json \
  --output table \
  --output forward:tcp://fluentd:24224

# 一个输出到终端，一个发送到 SIEM
tracee \
  --output table \
  --output webhook:https://siem.example.com/api/events
```

---

## 7. Metrics 输出 (Prometheus)

### 7.1 Stats 统计结构

`pkg/metrics/stats.go` 定义了所有收集的指标：

```go
type Stats struct {
    EventCount       *counter.Counter  // 处理的事件总数
    EventsFiltered   *counter.Counter  // 用户态过滤的事件数
    NetCapCount      *counter.Counter  // 网络捕获事件数
    BPFLogsCount     *counter.Counter  // BPF 日志数
    ErrorCount       *counter.Counter  // 错误数
    LostEvCount      *counter.Counter  // 丢失的事件数（提交缓冲区）
    LostWrCount      *counter.Counter  // 丢失的写入事件数
    LostNtCapCount   *counter.Counter  // 丢失的网络捕获事件数
    LostBPFLogsCount *counter.Counter  // 丢失的 BPF 日志数

    // BPF 级别的统计（需要 MetricsBuild）
    BPFPerfEventSubmitAttemptsCount *EventCollector
    BPFPerfEventSubmitFailuresCount *EventCollector

    Channels ChannelMetrics[*trace.Event]  // 通道指标
}

func NewStats() *Stats {
    stats := &Stats{
        EventCount:       counter.NewCounter(0),
        EventsFiltered:   counter.NewCounter(0),
        NetCapCount:      counter.NewCounter(0),
        BPFLogsCount:     counter.NewCounter(0),
        ErrorCount:       counter.NewCounter(0),
        LostEvCount:      counter.NewCounter(0),
        LostWrCount:      counter.NewCounter(0),
        LostNtCapCount:   counter.NewCounter(0),
        LostBPFLogsCount: counter.NewCounter(0),
        Channels:         make(ChannelMetrics[*trace.Event]),
    }

    if version.MetricsBuild() {
        stats.BPFPerfEventSubmitAttemptsCount = NewEventCollector(
            "Event submit attempts",
            prometheus.NewGaugeVec(
                prometheus.GaugeOpts{
                    Namespace: "tracee_ebpf",
                    Name:      "bpf_perf_event_submit_attempts",
                    Help:      "calls to submit to the event perf buffer",
                },
                []string{"event_name"},
            ),
        )
        // ... 更多指标
    }

    return stats
}
```

### 7.2 Prometheus 注册

```go
func (s *Stats) RegisterPrometheus() error {
    // 注册事件总数
    err := prometheus.Register(prometheus.NewCounterFunc(
        prometheus.CounterOpts{
            Namespace: "tracee_ebpf",
            Name:      "events_total",
            Help:      "events collected by tracee-ebpf",
        },
        func() float64 { return float64(s.EventCount.Get()) },
    ))
    if err != nil {
        return errfmt.WrapError(err)
    }

    // 注册过滤事件数
    err = prometheus.Register(prometheus.NewCounterFunc(
        prometheus.CounterOpts{
            Namespace: "tracee_ebpf",
            Name:      "events_filtered",
            Help:      "events filtered by tracee-ebpf in userspace",
        },
        func() float64 { return float64(s.EventsFiltered.Get()) },
    ))
    // ... 更多指标注册

    // 注册通道指标
    err = s.Channels.RegisterChannels()
    if err != nil {
        return errfmt.WrapError(err)
    }

    return nil
}
```

### 7.3 通道指标

监控内部通道的使用情况：

```go
// pkg/metrics/channels.go

type ChannelMetrics[T any] map[string]<-chan T

func (m ChannelMetrics[T]) RegisterChannels() error {
    for name, channel := range m {
        ch := channel  // 避免闭包问题

        gaugeVec := prometheus.NewGaugeFunc(
            prometheus.GaugeOpts{
                Namespace: "tracee_ebpf",
                Name:      fmt.Sprintf("pipeline_channels_%s", name),
                Help:      fmt.Sprintf("Pipeline channel %s", name),
            },
            func() float64 {
                return float64(len(ch))
            },
        )
        err := prometheus.Register(gaugeVec)
        if err != nil {
            return fmt.Errorf("failed to register channel %s: %w", name, err)
        }
    }
    return nil
}
```

### 7.4 HTTP 服务器

`pkg/server/http/server.go` 提供 Prometheus 指标端点：

```go
type Server struct {
    hs             *http.Server
    mux            *http.ServeMux
    metricsEnabled bool
    pyroProfiler   *pyroscope.Profiler
}

func New(listenAddr string) *Server {
    mux := http.NewServeMux()
    return &Server{
        hs: &http.Server{
            Addr:    listenAddr,
            Handler: mux,
        },
        mux: mux,
    }
}

func (s *Server) EnableMetricsEndpoint() {
    s.mux.Handle("/metrics", promhttp.Handler())
    s.metricsEnabled = true
}

func (s *Server) EnableHealthzEndpoint() {
    s.mux.HandleFunc("/healthz", func(w http.ResponseWriter, req *http.Request) {
        if heartbeat.GetInstance() != nil && heartbeat.GetInstance().IsAlive() {
            fmt.Fprintf(w, "OK")
            return
        }
        fmt.Fprintf(w, "NOT OK")
    })
}

func (s *Server) EnablePProfEndpoint() {
    s.mux.HandleFunc("/debug/pprof/", pprof.Index)
    s.mux.Handle("/debug/pprof/allocs", pprof.Handler("allocs"))
    s.mux.Handle("/debug/pprof/heap", pprof.Handler("heap"))
    // ... 更多 pprof 端点
}
```

### 7.5 可用指标列表

| 指标名称 | 类型 | 描述 |
|---------|------|------|
| `tracee_ebpf_events_total` | Counter | 收集的事件总数 |
| `tracee_ebpf_events_filtered` | Counter | 用户态过滤的事件数 |
| `tracee_ebpf_network_capture_events_total` | Counter | 网络捕获事件数 |
| `tracee_ebpf_bpf_logs_total` | Counter | BPF 日志总数 |
| `tracee_ebpf_errors_total` | Counter | 错误总数 |
| `tracee_ebpf_lostevents_total` | Counter | 丢失的事件数 |
| `tracee_ebpf_write_lostevents_total` | Counter | 写入缓冲区丢失事件数 |
| `tracee_ebpf_network_capture_lostevents_total` | Counter | 网络捕获丢失事件数 |
| `tracee_ebpf_bpf_perf_event_submit_attempts` | Gauge | BPF 事件提交尝试次数 |
| `tracee_ebpf_bpf_perf_event_submit_failures` | Gauge | BPF 事件提交失败次数 |
| `tracee_ebpf_pipeline_channels_*` | Gauge | 管道通道缓冲使用量 |

---

## 8. 自定义输出插件开发

### 8.1 实现 EventPrinter 接口

创建自定义输出插件的步骤：

```go
// custom_printer.go

package printer

import (
    "github.com/aquasecurity/tracee/pkg/metrics"
    "github.com/aquasecurity/tracee/types/trace"
)

// CustomPrinter 发送事件到自定义目标
type CustomPrinter struct {
    endpoint   string
    apiKey     string
    batchSize  int
    buffer     []trace.Event
    // ... 其他配置
}

// Init 初始化连接
func (p *CustomPrinter) Init() error {
    // 建立连接、验证配置等
    p.buffer = make([]trace.Event, 0, p.batchSize)
    return nil
}

// Preamble 输出开始前的处理
func (p *CustomPrinter) Preamble() {
    // 可选：输出头部信息
}

// Print 处理单个事件
func (p *CustomPrinter) Print(event trace.Event) {
    p.buffer = append(p.buffer, event)

    // 批量发送
    if len(p.buffer) >= p.batchSize {
        p.flush()
    }
}

// Epilogue 输出结束后的处理
func (p *CustomPrinter) Epilogue(stats metrics.Stats) {
    // 刷新剩余事件
    p.flush()

    // 可选：输出统计信息
}

// Close 清理资源
func (p *CustomPrinter) Close() {
    // 关闭连接等
}

func (p *CustomPrinter) flush() {
    if len(p.buffer) == 0 {
        return
    }

    // 发送事件到自定义端点
    // ... 实现发送逻辑

    p.buffer = p.buffer[:0]
}
```

### 8.2 注册自定义 Printer

在工厂方法中添加支持：

```go
func New(cfg config.PrinterConfig) (EventPrinter, error) {
    var res EventPrinter
    kind := cfg.Kind

    switch {
    // ... 现有类型

    case strings.HasPrefix(kind, "custom:"):
        endpoint := strings.TrimPrefix(kind, "custom:")
        res = &CustomPrinter{
            endpoint:  endpoint,
            batchSize: 100,
        }
    }

    err := res.Init()
    if err != nil {
        return nil, err
    }
    return res, nil
}
```

### 8.3 Kafka 输出示例

```go
type kafkaEventPrinter struct {
    brokers   []string
    topic     string
    producer  *kafka.Producer
    batchSize int
    buffer    []trace.Event
}

func (p *kafkaEventPrinter) Init() error {
    config := kafka.ConfigMap{
        "bootstrap.servers": strings.Join(p.brokers, ","),
    }

    producer, err := kafka.NewProducer(&config)
    if err != nil {
        return err
    }

    p.producer = producer
    p.buffer = make([]trace.Event, 0, p.batchSize)
    return nil
}

func (p *kafkaEventPrinter) Print(event trace.Event) {
    data, err := json.Marshal(event)
    if err != nil {
        return
    }

    message := &kafka.Message{
        TopicPartition: kafka.TopicPartition{
            Topic:     &p.topic,
            Partition: kafka.PartitionAny,
        },
        Key:   []byte(event.EventName),
        Value: data,
    }

    p.producer.Produce(message, nil)
}

func (p *kafkaEventPrinter) Close() {
    p.producer.Flush(15 * 1000)
    p.producer.Close()
}
```

### 8.4 Elasticsearch 输出示例

```go
type elasticEventPrinter struct {
    client    *elasticsearch.Client
    indexName string
    buffer    []map[string]interface{}
    batchSize int
}

func (p *elasticEventPrinter) Print(event trace.Event) {
    doc := map[string]interface{}{
        "@timestamp":  time.Unix(0, int64(event.Timestamp)).Format(time.RFC3339),
        "event_name":  event.EventName,
        "process":     event.ProcessName,
        "pid":         event.ProcessID,
        "container":   event.Container.ID,
        "args":        event.Args,
    }

    p.buffer = append(p.buffer, doc)

    if len(p.buffer) >= p.batchSize {
        p.bulkIndex()
    }
}

func (p *elasticEventPrinter) bulkIndex() {
    var buf bytes.Buffer

    for _, doc := range p.buffer {
        meta := map[string]interface{}{
            "index": map[string]interface{}{
                "_index": p.indexName,
            },
        }

        json.NewEncoder(&buf).Encode(meta)
        json.NewEncoder(&buf).Encode(doc)
    }

    p.client.Bulk(bytes.NewReader(buf.Bytes()))
    p.buffer = p.buffer[:0]
}
```

---

## 9. 与外部系统集成

### 9.1 Loki/Promtail 集成

#### 方式一：使用 Promtail 抓取日志文件

```yaml
# promtail-config.yaml
server:
  http_listen_port: 9080
  grpc_listen_port: 0

positions:
  filename: /tmp/positions.yaml

clients:
  - url: http://loki:3100/loki/api/v1/push

scrape_configs:
  - job_name: tracee
    static_configs:
      - targets:
          - localhost
        labels:
          job: tracee
          __path__: /var/log/tracee/events.json

    pipeline_stages:
      - json:
          expressions:
            event_name: eventName
            process_name: processName
            process_id: processId
            container_id: containerId
      - labels:
          event_name:
          process_name:
          container_id:
```

#### 方式二：使用 Forward 到 Loki

```bash
# 通过 Fluent Bit 转发到 Loki
tracee --output forward:tcp://fluent-bit:24224?tag=tracee
```

Fluent Bit 配置：

```ini
[INPUT]
    Name forward
    Listen 0.0.0.0
    Port 24224

[OUTPUT]
    Name loki
    Match *
    Host loki
    Port 3100
    Labels job=tracee
```

### 9.2 Grafana Dashboard

创建 Grafana Dashboard 展示 Tracee 数据：

```json
{
  "title": "Tracee Security Events",
  "panels": [
    {
      "title": "Events per Second",
      "type": "graph",
      "targets": [
        {
          "expr": "rate(tracee_ebpf_events_total[1m])",
          "legendFormat": "events/s"
        }
      ]
    },
    {
      "title": "Events by Type",
      "type": "piechart",
      "targets": [
        {
          "expr": "sum by (event_name) (rate(tracee_ebpf_events_total[5m]))",
          "legendFormat": "{{event_name}}"
        }
      ]
    },
    {
      "title": "Lost Events",
      "type": "stat",
      "targets": [
        {
          "expr": "tracee_ebpf_lostevents_total",
          "legendFormat": "Lost Events"
        }
      ]
    },
    {
      "title": "Recent Security Events (Loki)",
      "type": "logs",
      "datasource": "Loki",
      "targets": [
        {
          "expr": "{job=\"tracee\"} |= \"security\""
        }
      ]
    }
  ]
}
```

### 9.3 SIEM 系统集成

#### Splunk 集成

使用 Webhook 输出到 Splunk HEC：

```bash
tracee --output webhook:https://splunk.example.com:8088/services/collector?gotemplate=/etc/tracee/splunk.tmpl
```

Splunk HEC 模板：

```go
// splunk.tmpl
{
    "time": {{ div .Timestamp 1000000000 }},
    "host": "{{ .HostName }}",
    "source": "tracee",
    "sourcetype": "tracee:events",
    "event": {
        "event_name": "{{ .EventName }}",
        "process_name": "{{ .ProcessName }}",
        "process_id": {{ .ProcessID }},
        "user_id": {{ .UserID }},
        "container_id": "{{ .Container.ID }}",
        "args": [{{ range $i, $arg := .Args }}{{ if $i }},{{ end }}{"name":"{{ $arg.Name }}","value":"{{ $arg.Value }}"}{{ end }}]
    }
}
```

#### Elastic SIEM 集成

使用 Filebeat 收集 JSON 日志：

```yaml
# filebeat.yml
filebeat.inputs:
  - type: log
    enabled: true
    paths:
      - /var/log/tracee/events.json
    json:
      keys_under_root: true
      add_error_key: true

processors:
  - rename:
      fields:
        - from: "eventName"
          to: "event.action"
        - from: "processName"
          to: "process.name"
        - from: "processId"
          to: "process.pid"
  - add_fields:
      target: event
      fields:
        module: tracee
        dataset: tracee.events

output.elasticsearch:
  hosts: ["elasticsearch:9200"]
  index: "tracee-events-%{+yyyy.MM.dd}"
```

### 9.4 AWS CloudWatch 集成

```go
type cloudwatchEventPrinter struct {
    client     *cloudwatchlogs.Client
    logGroup   string
    logStream  string
    buffer     []types.InputLogEvent
    batchSize  int
}

func (p *cloudwatchEventPrinter) Print(event trace.Event) {
    data, _ := json.Marshal(event)

    logEvent := types.InputLogEvent{
        Message:   aws.String(string(data)),
        Timestamp: aws.Int64(event.Timestamp / 1000000), // 转换为毫秒
    }

    p.buffer = append(p.buffer, logEvent)

    if len(p.buffer) >= p.batchSize {
        p.flush()
    }
}

func (p *cloudwatchEventPrinter) flush() {
    _, _ = p.client.PutLogEvents(context.TODO(), &cloudwatchlogs.PutLogEventsInput{
        LogGroupName:  aws.String(p.logGroup),
        LogStreamName: aws.String(p.logStream),
        LogEvents:     p.buffer,
    })
    p.buffer = p.buffer[:0]
}
```

---

## 10. 动手练习

### 练习 1: 基本输出格式

**目标**: 理解不同输出格式的差异

```bash
# 1. 启动 Tracee，使用 JSON 格式输出
sudo tracee --output json --events execve,openat | head -20

# 2. 使用表格格式
sudo tracee --output table --events execve | head -20

# 3. 使用详细表格格式
sudo tracee --output table-verbose --events execve | head -20

# 4. 对比不同格式的输出大小
sudo timeout 10 tracee --output json --events execve > /tmp/json.log
sudo timeout 10 tracee --output table --events execve > /tmp/table.log
ls -lh /tmp/*.log
```

### 练习 2: 自定义模板输出

**目标**: 创建自定义的 Go 模板

```bash
# 1. 创建简单模板
cat > /tmp/simple.tmpl << 'EOF'
{{ .EventName }} | PID={{ .ProcessID }} | {{ .ProcessName }} | {{ range .Args }}{{ .Name }}={{ .Value }} {{ end }}
EOF

# 2. 使用模板
sudo tracee --output gotemplate=/tmp/simple.tmpl --events execve | head -10

# 3. 创建 CSV 格式模板
cat > /tmp/csv.tmpl << 'EOF'
{{ .Timestamp }},{{ .EventName }},{{ .ProcessID }},{{ .ProcessName }},"{{ range $i, $arg := .Args }}{{ if $i }};{{ end }}{{ $arg.Name }}={{ $arg.Value }}{{ end }}"
EOF

# 4. 输出 CSV
echo "Timestamp,Event,PID,Process,Args" > /tmp/events.csv
sudo tracee --output gotemplate=/tmp/csv.tmpl --events execve,openat >> /tmp/events.csv
```

### 练习 3: 多输出目标

**目标**: 配置同时输出到多个目标

```bash
# 1. 同时输出到终端和文件
sudo tracee \
  --output table \
  --output json:/tmp/tracee-events.json \
  --events execve &

# 2. 在另一个终端监控 JSON 文件
tail -f /tmp/tracee-events.json | jq .

# 3. 停止 Tracee
pkill tracee
```

### 练习 4: Prometheus 指标

**目标**: 配置和查看 Prometheus 指标

```bash
# 1. 启用 metrics 端点
sudo tracee --metrics --listen-addr :3366 &

# 2. 查看可用指标
curl -s http://localhost:3366/metrics | grep tracee

# 3. 生成一些事件
for i in {1..100}; do ls /tmp > /dev/null; done

# 4. 再次查看指标变化
curl -s http://localhost:3366/metrics | grep tracee_ebpf_events_total
```

### 练习 5: gRPC 流式输出

**目标**: 使用 traceectl 接收事件流

```bash
# 1. 启动 Tracee（开启 gRPC）
sudo tracee --grpc-listen-addr unix:/var/run/tracee.sock &

# 2. 使用 traceectl 连接
traceectl --server unix:/var/run/tracee.sock stream --output json | head -20

# 3. 使用表格格式
traceectl --server unix:/var/run/tracee.sock stream --output table
```

### 练习 6: 实现简单的自定义 Printer

**目标**: 创建一个计数 Printer

创建文件 `counting_printer.go`:

```go
package main

import (
    "fmt"
    "sync/atomic"
    "time"

    "github.com/aquasecurity/tracee/pkg/metrics"
    "github.com/aquasecurity/tracee/types/trace"
)

type countingPrinter struct {
    eventCounts map[string]*int64
    startTime   time.Time
}

func newCountingPrinter() *countingPrinter {
    return &countingPrinter{
        eventCounts: make(map[string]*int64),
        startTime:   time.Now(),
    }
}

func (p *countingPrinter) Init() error {
    return nil
}

func (p *countingPrinter) Preamble() {
    fmt.Println("Starting event counting...")
}

func (p *countingPrinter) Print(event trace.Event) {
    if _, exists := p.eventCounts[event.EventName]; !exists {
        p.eventCounts[event.EventName] = new(int64)
    }
    atomic.AddInt64(p.eventCounts[event.EventName], 1)
}

func (p *countingPrinter) Epilogue(stats metrics.Stats) {
    duration := time.Since(p.startTime)
    fmt.Printf("\n=== Event Statistics (Duration: %s) ===\n", duration)

    var total int64
    for name, count := range p.eventCounts {
        c := atomic.LoadInt64(count)
        total += c
        fmt.Printf("  %-30s: %d\n", name, c)
    }

    fmt.Printf("\nTotal events: %d\n", total)
    fmt.Printf("Events per second: %.2f\n", float64(total)/duration.Seconds())
}

func (p *countingPrinter) Close() {}
```

### 练习 7: 与 Loki 集成

**目标**: 将 Tracee 事件发送到 Loki

```bash
# 1. 启动 Loki (使用 Docker)
docker run -d --name loki -p 3100:3100 grafana/loki:latest

# 2. 创建 Fluent Bit 配置
cat > /tmp/fluent-bit.conf << 'EOF'
[SERVICE]
    Flush        1
    Log_Level    info

[INPUT]
    Name         forward
    Listen       0.0.0.0
    Port         24224

[OUTPUT]
    Name         loki
    Match        *
    Host         localhost
    Port         3100
    Labels       job=tracee
EOF

# 3. 启动 Fluent Bit
docker run -d --name fluent-bit --network host \
  -v /tmp/fluent-bit.conf:/fluent-bit/etc/fluent-bit.conf \
  fluent/fluent-bit:latest

# 4. 启动 Tracee
sudo tracee --output forward:tcp://localhost:24224?tag=tracee

# 5. 查询 Loki
curl -G 'http://localhost:3100/loki/api/v1/query_range' \
  --data-urlencode 'query={job="tracee"}' \
  --data-urlencode 'limit=10'
```

---

## 11. 核心代码走读

### 11.1 事件流管理 (streams.go)

**文件**: `pkg/streams/streams.go`

```go
// Stream 表示一个事件流
type Stream struct {
    // 策略掩码：此流感兴趣的策略位图
    policyMask uint64
    // 事件通道：用于从流接收事件
    events chan trace.Event
}

// ReceiveEvents 返回只读通道用于接收事件
func (s *Stream) ReceiveEvents() <-chan trace.Event {
    return s.events
}

// publish 发布事件到流（内部方法）
func (s *Stream) publish(ctx context.Context, event trace.Event) {
    // 检查策略匹配
    if s.shouldIgnorePolicy(event) {
        return
    }

    // 阻塞发送或上下文取消
    select {
    case s.events <- event:
    case <-ctx.Done():
        return
    }
}

// shouldIgnorePolicy 检查是否应该忽略此事件
func (s *Stream) shouldIgnorePolicy(event trace.Event) bool {
    return s.policyMask&event.MatchedPoliciesUser == 0
}
```

**StreamsManager 管理多个订阅者**:

```go
type StreamsManager struct {
    mutex       sync.Mutex
    subscribers map[*Stream]struct{}
}

// Subscribe 创建新的订阅流
func (sm *StreamsManager) Subscribe(policyMask uint64, chanSize int) *Stream {
    sm.mutex.Lock()
    defer sm.mutex.Unlock()

    stream := &Stream{
        policyMask: policyMask,
        events:     make(chan trace.Event, chanSize),
    }

    sm.subscribers[stream] = struct{}{}
    return stream
}

// Publish 向所有订阅者发布事件
func (sm *StreamsManager) Publish(ctx context.Context, event trace.Event) {
    sm.mutex.Lock()
    defer sm.mutex.Unlock()

    for stream := range sm.subscribers {
        stream.publish(ctx, event)
    }
}
```

### 11.2 gRPC 事件数据转换 (event_data.go)

**文件**: `pkg/server/grpc/event_data.go`

```go
// getEventData 将事件参数转换为 protobuf 格式
func getEventData(e trace.Event) ([]*pb.EventValue, error) {
    data := make([]*pb.EventValue, 0)

    for _, arg := range e.Args {
        // 跳过 triggeredBy（单独处理）
        if arg.ArgMeta.Name == "triggeredBy" {
            continue
        }

        eventValue, err := getEventValue(arg)
        if err != nil {
            return nil, err
        }

        if eventValue == nil {
            // 不支持的类型
            logger.Errorw(
                "Can't convert event argument",
                "name", arg.Name,
                "type", fmt.Sprintf("%T", arg.Value),
            )
            continue
        }

        eventValue.Name = sanitizeStringForProtobuf(arg.ArgMeta.Name)
        data = append(data, eventValue)
    }

    // 添加系统调用返回值
    if events.Core.GetDefinitionByID(events.ID(e.EventID)).IsSyscall() {
        data = append(data, &pb.EventValue{
            Name: "returnValue",
            Value: &pb.EventValue_Int64{
                Int64: int64(e.ReturnValue),
            },
        })
    }

    return data, nil
}

// parseArgument 将参数值转换为对应的 protobuf 类型
func parseArgument(arg trace.Argument) (*pb.EventValue, error) {
    switch v := arg.Value.(type) {
    case nil:
        return &pb.EventValue{Value: nil}, nil
    case int:
        return &pb.EventValue{
            Value: &pb.EventValue_Int64{Int64: int64(v)},
        }, nil
    case string:
        return &pb.EventValue{
            Value: &pb.EventValue_Str{
                Str: sanitizeStringForProtobuf(v),
            },
        }, nil
    case []string:
        return &pb.EventValue{
            Value: &pb.EventValue_StrArray{
                StrArray: &pb.StringArray{
                    Value: sanitizeStringArrayForProtobuf(v),
                },
            },
        }, nil
    case trace.SlimCred:
        return &pb.EventValue{
            Value: &pb.EventValue_Credentials{
                Credentials: &pb.Credentials{
                    Uid:  wrapperspb.UInt32(v.Uid),
                    Gid:  wrapperspb.UInt32(v.Gid),
                    // ... 更多字段
                },
            },
        }, nil
    // ... 更多类型处理
    }

    return convertToStruct(arg)
}

// sanitizeStringForProtobuf 确保字符串是有效的 UTF-8
func sanitizeStringForProtobuf(s string) string {
    if utf8.ValidString(s) {
        return s
    }

    var builder strings.Builder
    builder.Grow(len(s))

    for len(s) > 0 {
        r, size := utf8.DecodeRuneInString(s)
        if r != utf8.RuneError {
            builder.WriteRune(r)
        }
        s = s[size:]
    }

    return builder.String()
}
```

### 11.3 EventCollector 实现 (event_collector.go)

**文件**: `pkg/metrics/event_collector.go`

```go
// EventCollector 按事件类型收集指标
type EventCollector struct {
    c *Collector[events.ID]
}

func NewEventCollector(description string, gv *prometheus.GaugeVec) *EventCollector {
    return &EventCollector{
        c: NewCollector[events.ID](description, gv),
    }
}

func (ec *EventCollector) Get(id events.ID) uint64 {
    v, ok := ec.c.Get(id)
    if !ok {
        logger.Errorw("Failed to get value from event collector", "event_id", id)
    }
    return v
}

func (ec *EventCollector) Set(id events.ID, v uint64) {
    ec.c.Set(id, v)
}

// Log 输出当前收集的所有指标
func (ec *EventCollector) Log() {
    values := ec.c.Values()
    description := ec.c.Description()

    keyVals := make([]interface{}, 0, len(values)*2+1)
    total := counter.NewCounter(0)

    for k, v := range values {
        keyVals = append(keyVals,
            events.Core.GetDefinitionByID(events.ID(k)).GetName(),
            v,
        )
        total.Increment(v)
    }

    keyVals = append(keyVals, "total", total.Get())
    logger.Infow(description, keyVals...)
}
```

### 11.4 代码阅读建议

1. **从 Printer 接口开始**:
   - 首先理解 `EventPrinter` 接口的定义
   - 然后阅读各种实现（json、table、template）

2. **理解事件流向**:
   - 从 `StreamsManager` 开始
   - 追踪事件如何从订阅到输出

3. **关注序列化细节**:
   - 查看 `parseArgument` 函数处理的所有类型
   - 理解 protobuf 转换逻辑

4. **调试技巧**:
   - 使用 `--log-level debug` 查看详细日志
   - 使用 ignore Printer 测试事件处理性能

---

## 总结

Tracee 的输出管道是一个精心设计的模块化系统：

1. **事件流管理**: `StreamsManager` 提供灵活的订阅发布机制
2. **序列化层**: 支持多种格式（JSON、Table、Template、Protobuf）
3. **输出目标**: 支持本地输出和网络输出（Forward、Webhook、gRPC）
4. **指标收集**: 与 Prometheus 完美集成
5. **可扩展性**: 通过 `EventPrinter` 接口支持自定义输出

通过本教程的学习，你应该能够：
- 根据需求选择合适的输出格式和目标
- 创建自定义的输出模板和 Printer
- 将 Tracee 与企业 SIEM 和可观测性平台集成
- 通过 Prometheus 监控 Tracee 的运行状态

---

## 参考资料

- [Tracee 官方文档](https://aquasecurity.github.io/tracee/)
- [Prometheus Go Client](https://github.com/prometheus/client_golang)
- [gRPC Go 文档](https://grpc.io/docs/languages/go/)
- [Fluent Forward Protocol](https://github.com/fluent/fluentd/wiki/Forward-Protocol-Specification-v1)
- [Go Template 语法](https://pkg.go.dev/text/template)
- [Sprig 模板函数](http://masterminds.github.io/sprig/)
