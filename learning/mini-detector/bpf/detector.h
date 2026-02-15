/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __DETECTOR_H__
#define __DETECTOR_H__

// 事件类型
enum event_type {
    EVENT_NONE = 0,
    EVENT_PRIV_ESCALATION = 1,  // 提权事件
    EVENT_FILE_ACCESS = 2,       // 文件访问事件
};

// 基础事件结构（所有事件共有）
struct event_base {
    __u32 type;          // 事件类型
    __u32 pid;           // 进程 ID
    __u32 tid;           // 线程 ID
    __u32 ppid;          // 父进程 ID
    __u32 uid;           // 用户 ID
    __u32 _pad;          // 填充对齐
    __u64 timestamp;     // 时间戳
    char comm[16];       // 进程名
    char parent_comm[16]; // 父进程名
};

// 提权事件
struct priv_escalation_event {
    struct event_base base;
    __u32 old_uid;
    __u32 new_uid;
    __u32 old_euid;
    __u32 new_euid;
};

// 文件访问事件
struct file_access_event {
    struct event_base base;
    __u32 flags;
    __u32 _pad;
    char filename[64];
};

#define MAX_FILENAME_LEN 64

#endif /* __DETECTOR_H__ */
