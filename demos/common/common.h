// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Common definitions for eBPF learning demos
// Reference: Tracee pkg/ebpf/c/common/common.h

#ifndef __COMMON_H
#define __COMMON_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// ============================================================================
// Common Constants
// ============================================================================

#define TASK_COMM_LEN      16
#define MAX_FILENAME_LEN   256
#define MAX_PATH_LEN       4096
#define MAX_ARGS           20
#define MAX_ARG_LEN        256

// ============================================================================
// Common Macros (inspired by Tracee)
// ============================================================================

// Likely/Unlikely hints for branch prediction
#define likely(x)   __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

// Static inline function marker
#define statfunc static __always_inline

// Read-only after init section
#define READ_KERN(ptr)                                                         \
    ({                                                                         \
        typeof(ptr) _val;                                                      \
        __builtin_memset((void *)&_val, 0, sizeof(_val));                     \
        bpf_core_read((void *)&_val, sizeof(_val), &ptr);                     \
        _val;                                                                  \
    })

// ============================================================================
// Common Event Structure (base for all demos)
// ============================================================================

// Base event context - similar to Tracee's task_context_t
struct event_base {
    u64 timestamp;           // Event timestamp (nanoseconds)
    u32 pid;                 // Process ID (userspace view)
    u32 tid;                 // Thread ID
    u32 ppid;                // Parent process ID
    u32 uid;                 // User ID
    u32 gid;                 // Group ID
    char comm[TASK_COMM_LEN]; // Process name
};

// ============================================================================
// Helper Functions
// ============================================================================

// Get current timestamp in nanoseconds
statfunc u64 get_current_time_ns(void)
{
    return bpf_ktime_get_ns();
}

// Fill base event info from current task
statfunc void fill_event_base(struct event_base *e)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 uid_gid = bpf_get_current_uid_gid();

    e->timestamp = get_current_time_ns();
    e->pid = pid_tgid >> 32;          // Upper 32 bits = TGID (PID)
    e->tid = (u32)pid_tgid;           // Lower 32 bits = TID
    e->uid = (u32)uid_gid;            // Lower 32 bits = UID
    e->gid = uid_gid >> 32;           // Upper 32 bits = GID

    bpf_get_current_comm(&e->comm, sizeof(e->comm));
}

// Get parent PID from task_struct
// Reference: Tracee pkg/ebpf/c/common/task.h
statfunc u32 get_ppid(struct task_struct *task)
{
    struct task_struct *parent;
    parent = BPF_CORE_READ(task, real_parent);
    return BPF_CORE_READ(parent, tgid);
}

// Fill event base with parent info
statfunc void fill_event_base_with_parent(struct event_base *e)
{
    fill_event_base(e);

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    e->ppid = get_ppid(task);
}

// ============================================================================
// Map Helper Macros
// ============================================================================

// Define a perf event array for output
#define DEFINE_PERF_EVENT_ARRAY(name)                                          \
    struct {                                                                   \
        __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);                           \
        __uint(key_size, sizeof(int));                                         \
        __uint(value_size, sizeof(int));                                       \
    } name SEC(".maps")

// Define a hash map
#define DEFINE_HASH_MAP(name, key_type, value_type, max_entries)               \
    struct {                                                                   \
        __uint(type, BPF_MAP_TYPE_HASH);                                       \
        __uint(max_entries, max_entries);                                      \
        __type(key, key_type);                                                 \
        __type(value, value_type);                                             \
    } name SEC(".maps")

// Define an LRU hash map
#define DEFINE_LRU_HASH_MAP(name, key_type, value_type, max_entries)           \
    struct {                                                                   \
        __uint(type, BPF_MAP_TYPE_LRU_HASH);                                   \
        __uint(max_entries, max_entries);                                      \
        __type(key, key_type);                                                 \
        __type(value, value_type);                                             \
    } name SEC(".maps")

// Define a per-CPU array
#define DEFINE_PERCPU_ARRAY(name, value_type, max_entries)                     \
    struct {                                                                   \
        __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);                               \
        __uint(max_entries, max_entries);                                      \
        __type(key, u32);                                                      \
        __type(value, value_type);                                             \
    } name SEC(".maps")

// Define a ring buffer (kernel >= 5.8)
#define DEFINE_RING_BUFFER(name, size)                                         \
    struct {                                                                   \
        __uint(type, BPF_MAP_TYPE_RINGBUF);                                    \
        __uint(max_entries, size);                                             \
    } name SEC(".maps")

// ============================================================================
// Debug Helpers
// ============================================================================

// Print debug message (only for development, remove in production)
// View output: sudo cat /sys/kernel/debug/tracing/trace_pipe
#ifdef DEBUG
#define bpf_debug(fmt, ...)  bpf_printk(fmt, ##__VA_ARGS__)
#else
#define bpf_debug(fmt, ...)  do {} while (0)
#endif

// ============================================================================
// Error Codes
// ============================================================================

#define ERR_MAP_LOOKUP_FAILED  -1
#define ERR_MAP_UPDATE_FAILED  -2
#define ERR_PROBE_READ_FAILED  -3
#define ERR_BUFFER_FULL        -4

// ============================================================================
// License (required for all eBPF programs)
// ============================================================================

#define LICENSE_SECTION char _license[] SEC("license") = "Dual BSD/GPL"

#endif /* __COMMON_H */
