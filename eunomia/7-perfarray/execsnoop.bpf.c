// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "execsnoop.h"

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 100);
    __type(key, __u32);
    __type(value, struct event);
} values SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint_syscalls_sys_enter_execve(struct trace_event_raw_sys_enter* ctx)
{
    u64 id;
    pid_t pid, tgid;
    struct event event={0};
    struct task_struct *task;

    uid_t uid = (u32)bpf_get_current_uid_gid();
    id = bpf_get_current_pid_tgid();
    tgid = id >> 32;

    event.pid = tgid;
    event.uid = uid;
    task = (struct task_struct*)bpf_get_current_task();
    event.ppid = BPF_CORE_READ(task, real_parent, tgid);
    char *cmd_ptr = (char *) BPF_CORE_READ(ctx, args[0]);
    bpf_probe_read_str(&event.comm, sizeof(event.comm), cmd_ptr);
    bpf_map_update_elem(&values, &id, &event, BPF_ANY);
    return 0;
}


SEC("tracepoint/syscalls/sys_exit_execve")
int tracepoint_syscalls_sys_exit_execve(struct trace_event_raw_sys_exit* ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = (__u32)pid_tgid;
    struct event *eventp;
        
    eventp = bpf_map_lookup_elem(&values, &tid);
    if (!eventp)
      return 0;

    eventp->retval = ctx->ret;

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, eventp, sizeof(struct event));

cleanup:
  bpf_map_delete_elem(&values, &tid);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
