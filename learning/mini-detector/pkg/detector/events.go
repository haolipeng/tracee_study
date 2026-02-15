package detector

// 事件类型常量（与 eBPF 程序中的定义对应）
const (
    EventNone           = 0
    EventPrivEscalation = 1
    EventFileAccess     = 2
)

// 基础事件结构（与 eBPF 中的 struct event_base 对应）
type EventBase struct {
    Type       uint32
    PID        uint32
    TID        uint32
    PPID       uint32
    UID        uint32
    Pad        uint32
    Timestamp  uint64
    Comm       [16]byte
    ParentComm [16]byte
}

// 提权事件（与 eBPF 中的 struct priv_escalation_event 对应）
type PrivEscalationEvent struct {
    Base    EventBase
    OldUID  uint32
    NewUID  uint32
    OldEUID uint32
    NewEUID uint32
}

// 文件访问事件（与 eBPF 中的 struct file_access_event 对应）
type FileAccessEvent struct {
    Base     EventBase
    Flags    uint32
    Pad      uint32
    Filename [64]byte
}

// 通用事件（用于 JSON 输出）
type Event struct {
    Type       string                 `json:"type"`
    Timestamp  uint64                 `json:"timestamp"`
    PID        uint32                 `json:"pid"`
    TID        uint32                 `json:"tid"`
    PPID       uint32                 `json:"ppid"`
    UID        uint32                 `json:"uid"`
    Comm       string                 `json:"comm"`
    ParentComm string                 `json:"parent_comm"`
    Details    map[string]interface{} `json:"details"`
    Severity   string                 `json:"severity"`
}
