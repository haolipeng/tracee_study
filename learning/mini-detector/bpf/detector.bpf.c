// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "detector.h"

// Ring Buffer 用于向用户空间发送事件
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // 256KB
} events SEC(".maps");

// 敏感文件名 Map
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, char[MAX_FILENAME_LEN]);
    __type(value, __u8);
} sensitive_files SEC(".maps");

// 辅助函数：填充基础事件信息
static __always_inline void fill_event_base(struct event_base *base, __u32 type) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent;

    base->type = type;
    base->timestamp = bpf_ktime_get_ns();

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    base->pid = pid_tgid >> 32;
    base->tid = pid_tgid & 0xFFFFFFFF;
    base->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    bpf_get_current_comm(&base->comm, sizeof(base->comm));

    // 获取父进程信息
    BPF_CORE_READ_INTO(&parent, task, real_parent);
    if (parent) {
        BPF_CORE_READ_INTO(&base->ppid, parent, tgid);
        BPF_CORE_READ_STR_INTO(&base->parent_comm, parent, comm);
    }
}

// ============ 提权检测 ============

SEC("kprobe/commit_creds")
int BPF_KPROBE(trace_commit_creds, struct cred *new_cred)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    const struct cred *old_cred;

    // 获取旧凭证
    BPF_CORE_READ_INTO(&old_cred, task, real_cred);
    if (!old_cred || !new_cred)
        return 0;

    // 读取 UID/EUID
    __u32 old_uid, new_uid, old_euid, new_euid;

    old_uid = BPF_CORE_READ(old_cred, uid.val);
    new_uid = BPF_CORE_READ(new_cred, uid.val);
    old_euid = BPF_CORE_READ(old_cred, euid.val);
    new_euid = BPF_CORE_READ(new_cred, euid.val);

    // 检测提权：从非 root 变成 root
    if ((old_euid != 0 && new_euid == 0) ||
        (old_uid != 0 && new_uid == 0)) {

        // 分配 Ring Buffer 空间
        struct priv_escalation_event *e;
        e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
        if (!e)
            return 0;

        // 填充事件
        fill_event_base(&e->base, EVENT_PRIV_ESCALATION);
        e->old_uid = old_uid;
        e->new_uid = new_uid;
        e->old_euid = old_euid;
        e->new_euid = new_euid;

        // 提交事件
        bpf_ringbuf_submit(e, 0);
    }

    return 0;
}

// ============ 文件访问检测 ============

SEC("kprobe/security_file_open")
int BPF_KPROBE(trace_file_open, struct file *file)
{
    if (!file)
        return 0;

    // 获取文件名
    struct dentry *dentry;
    BPF_CORE_READ_INTO(&dentry, file, f_path.dentry);
    if (!dentry)
        return 0;

    char filename[MAX_FILENAME_LEN] = {};
    struct qstr d_name;
    BPF_CORE_READ_INTO(&d_name, dentry, d_name);
    bpf_probe_read_kernel_str(&filename, sizeof(filename), d_name.name);

    // 检查是否为敏感文件（通过 Map）
    __u8 *is_sensitive = bpf_map_lookup_elem(&sensitive_files, &filename);

    // 也检查硬编码的敏感文件
    bool is_shadow = (filename[0] == 's' && filename[1] == 'h' &&
                      filename[2] == 'a' && filename[3] == 'd' &&
                      filename[4] == 'o' && filename[5] == 'w' &&
                      filename[6] == '\0');

    bool is_passwd = (filename[0] == 'p' && filename[1] == 'a' &&
                      filename[2] == 's' && filename[3] == 's' &&
                      filename[4] == 'w' && filename[5] == 'd' &&
                      filename[6] == '\0');

    bool is_sudoers = (filename[0] == 's' && filename[1] == 'u' &&
                       filename[2] == 'd' && filename[3] == 'o' &&
                       filename[4] == 'e' && filename[5] == 'r' &&
                       filename[6] == 's' && filename[7] == '\0');

    if (is_sensitive || is_shadow || is_passwd || is_sudoers) {
        // 分配 Ring Buffer 空间
        struct file_access_event *e;
        e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
        if (!e)
            return 0;

        // 填充事件
        fill_event_base(&e->base, EVENT_FILE_ACCESS);
        BPF_CORE_READ_INTO(&e->flags, file, f_flags);

        // 复制文件名
        __builtin_memcpy(e->filename, filename, sizeof(e->filename));

        bpf_ringbuf_submit(e, 0);
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
