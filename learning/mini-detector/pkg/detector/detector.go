package detector

import (
    "bytes"
    "encoding/binary"
    "fmt"
    "syscall"

    "github.com/aquasecurity/libbpfgo"
)

// Detector 是主检测器结构
type Detector struct {
    module     *libbpfgo.Module
    ringbuf    *libbpfgo.RingBuffer
    eventsChan chan Event
    stopChan   chan struct{}
}

// New 创建新的检测器
func New(bpfObjPath string) (*Detector, error) {
    // 加载 BPF 程序
    module, err := libbpfgo.NewModuleFromFile(bpfObjPath)
    if err != nil {
        return nil, fmt.Errorf("failed to load BPF module: %w", err)
    }

    if err := module.BPFLoadObject(); err != nil {
        module.Close()
        return nil, fmt.Errorf("failed to load BPF object: %w", err)
    }

    return &Detector{
        module:     module,
        eventsChan: make(chan Event, 1000),
        stopChan:   make(chan struct{}),
    }, nil
}

// Start 启动检测器
func (d *Detector) Start() error {
    // 附加提权检测探针
    progPriv, err := d.module.GetProgram("trace_commit_creds")
    if err != nil {
        return fmt.Errorf("failed to get priv program: %w", err)
    }
    if _, err := progPriv.AttachKprobe("commit_creds"); err != nil {
        return fmt.Errorf("failed to attach priv kprobe: %w", err)
    }

    // 附加文件监控探针
    progFile, err := d.module.GetProgram("trace_file_open")
    if err != nil {
        return fmt.Errorf("failed to get file program: %w", err)
    }
    if _, err := progFile.AttachKprobe("security_file_open"); err != nil {
        return fmt.Errorf("failed to attach file kprobe: %w", err)
    }

    // 初始化敏感文件列表
    if err := d.initSensitiveFiles(); err != nil {
        fmt.Printf("Warning: failed to init sensitive files map: %v\n", err)
    }

    // 设置 Ring Buffer
    d.ringbuf, err = d.module.InitRingBuf("events", d.handleEvent)
    if err != nil {
        return fmt.Errorf("failed to init ring buffer: %w", err)
    }

    d.ringbuf.Poll(300) // 300ms 轮询

    return nil
}

// initSensitiveFiles 初始化敏感文件列表 Map
func (d *Detector) initSensitiveFiles() error {
    sensitiveMap, err := d.module.GetMap("sensitive_files")
    if err != nil {
        return err
    }

    // 敏感文件列表
    files := []string{
        "shadow", "passwd", "sudoers",
        "authorized_keys", "id_rsa", "id_ed25519",
        "docker.sock", "kcore", "id_ecdsa",
    }

    for _, f := range files {
        key := make([]byte, 64)
        copy(key, f)
        val := uint8(1)
        if err := sensitiveMap.Update(key, val); err != nil {
            fmt.Printf("Warning: failed to add %s to map: %v\n", f, err)
        }
    }

    return nil
}

// handleEvent 处理从 Ring Buffer 接收的事件
func (d *Detector) handleEvent(data []byte) {
    if len(data) < 4 {
        return
    }

    // 读取事件类型
    eventType := binary.LittleEndian.Uint32(data[0:4])

    var event Event

    switch eventType {
    case EventPrivEscalation:
        var e PrivEscalationEvent
        if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &e); err != nil {
            fmt.Printf("Failed to parse priv event: %v\n", err)
            return
        }
        event = d.parsePrivEvent(&e)

    case EventFileAccess:
        var e FileAccessEvent
        if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &e); err != nil {
            fmt.Printf("Failed to parse file event: %v\n", err)
            return
        }
        event = d.parseFileEvent(&e)

    default:
        return
    }

    // 发送事件到通道
    select {
    case d.eventsChan <- event:
    default:
        // 通道满了，丢弃事件
    }
}

// parsePrivEvent 解析提权事件
func (d *Detector) parsePrivEvent(e *PrivEscalationEvent) Event {
    severity := "HIGH"
    comm := cstring(e.Base.Comm[:])

    // 白名单检查
    if isWhitelisted(comm) {
        severity = "INFO"
    }

    return Event{
        Type:       "PRIVILEGE_ESCALATION",
        Timestamp:  e.Base.Timestamp,
        PID:        e.Base.PID,
        TID:        e.Base.TID,
        PPID:       e.Base.PPID,
        UID:        e.Base.UID,
        Comm:       comm,
        ParentComm: cstring(e.Base.ParentComm[:]),
        Severity:   severity,
        Details: map[string]interface{}{
            "old_uid":  e.OldUID,
            "new_uid":  e.NewUID,
            "old_euid": e.OldEUID,
            "new_euid": e.NewEUID,
        },
    }
}

// parseFileEvent 解析文件访问事件
func (d *Detector) parseFileEvent(e *FileAccessEvent) Event {
    accessType := "READ"
    if e.Flags&(syscall.O_WRONLY|syscall.O_RDWR) != 0 {
        accessType = "WRITE"
    }

    filename := cstring(e.Filename[:])
    severity := "MEDIUM"

    // shadow 文件优先级更高
    if filename == "shadow" {
        severity = "HIGH"
    }

    return Event{
        Type:       "SENSITIVE_FILE_ACCESS",
        Timestamp:  e.Base.Timestamp,
        PID:        e.Base.PID,
        TID:        e.Base.TID,
        PPID:       e.Base.PPID,
        UID:        e.Base.UID,
        Comm:       cstring(e.Base.Comm[:]),
        ParentComm: cstring(e.Base.ParentComm[:]),
        Severity:   severity,
        Details: map[string]interface{}{
            "filename":    filename,
            "access_type": accessType,
            "flags":       e.Flags,
        },
    }
}

// Events 返回事件通道
func (d *Detector) Events() <-chan Event {
    return d.eventsChan
}

// Stop 停止检测器
func (d *Detector) Stop() {
    close(d.stopChan)
    if d.ringbuf != nil {
        d.ringbuf.Stop()
    }
    if d.module != nil {
        d.module.Close()
    }
}

// cstring 将 C 字符串（以 null 结尾）转换为 Go 字符串
func cstring(b []byte) string {
    n := bytes.IndexByte(b, 0)
    if n == -1 {
        n = len(b)
    }
    return string(b[:n])
}

// isWhitelisted 检查进程名是否在白名单中
func isWhitelisted(comm string) bool {
    whitelist := []string{
        "sudo", "su", "login", "sshd", "cron",
        "polkitd", "systemd", "gdm", "lightdm",
    }
    for _, w := range whitelist {
        if comm == w {
            return true
        }
    }
    return false
}
