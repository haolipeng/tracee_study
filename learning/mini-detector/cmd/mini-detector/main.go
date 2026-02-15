package main

import (
    "encoding/json"
    "flag"
    "fmt"
    "os"
    "os/signal"
    "syscall"
    "time"

    "mini-detector/pkg/detector"
)

const banner = `
╔════════════════════════════════════════════════════╗
║         Mini eBPF Security Detector                ║
║                                                    ║
║  Detecting:                                        ║
║  - Privilege Escalation (UID changes to root)     ║
║  - Sensitive File Access (shadow, passwd, etc.)   ║
╚════════════════════════════════════════════════════╝
`

func main() {
    // 命令行参数
    bpfObj := flag.String("bpf", "bpf/detector.bpf.o", "Path to BPF object file")
    jsonOutput := flag.Bool("json", false, "Output in JSON format")
    flag.Parse()

    fmt.Print(banner)

    // 创建检测器
    det, err := detector.New(*bpfObj)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error: Failed to create detector: %v\n", err)
        fmt.Fprintf(os.Stderr, "Make sure you have:\n")
        fmt.Fprintf(os.Stderr, "  1. Run 'make all' to compile the eBPF program\n")
        fmt.Fprintf(os.Stderr, "  2. Run this program with sudo\n")
        os.Exit(1)
    }
    defer det.Stop()

    // 启动检测
    if err := det.Start(); err != nil {
        fmt.Fprintf(os.Stderr, "Error: Failed to start detector: %v\n", err)
        os.Exit(1)
    }

    fmt.Println("[*] Detector started successfully")
    fmt.Println("[*] Press Ctrl+C to exit")
    fmt.Println()

    // 处理信号
    sig := make(chan os.Signal, 1)
    signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

    // 主循环
    for {
        select {
        case event := <-det.Events():
            if *jsonOutput {
                printJSON(event)
            } else {
                printPretty(event)
            }

        case <-sig:
            fmt.Println("\n[*] Shutting down...")
            return
        }
    }
}

// printJSON 以 JSON 格式输出事件
func printJSON(event detector.Event) {
    data, err := json.Marshal(event)
    if err != nil {
        return
    }
    fmt.Println(string(data))
}

// printPretty 以友好格式输出事件
func printPretty(event detector.Event) {
    // 转换时间戳
    ts := time.Unix(0, int64(event.Timestamp)).Format("15:04:05.000")

    // 根据级别设置颜色
    var severityColor string
    switch event.Severity {
    case "HIGH":
        severityColor = "\033[31m" // 红色
    case "MEDIUM":
        severityColor = "\033[33m" // 黄色
    case "INFO":
        severityColor = "\033[32m" // 绿色
    default:
        severityColor = "\033[0m"
    }
    resetColor := "\033[0m"

    // 输出事件
    fmt.Printf("%s[%s]%s %s | %s\n",
        severityColor, event.Severity, resetColor,
        ts, event.Type)
    fmt.Printf("  Process: %s (PID: %d, PPID: %d, UID: %d)\n",
        event.Comm, event.PID, event.PPID, event.UID)
    fmt.Printf("  Parent:  %s\n", event.ParentComm)

    // 输出详细信息
    for k, v := range event.Details {
        fmt.Printf("  %s: %v\n", k, v)
    }
    fmt.Println()
}
