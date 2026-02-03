/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
// for compatibility with older kernels
#define BPF_NO_GLOBAL_DATA
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

typedef unsigned int u32;
typedef int pid_t;
const pid_t pid_filter = 0;

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// hook into tp = tracepoint, syscalls -> sys_enter_write
// for listing the syscalls:
// sudo ls /sys/kernel/debug/tracing/events/syscalls/
SEC("tp/syscalls/sys_enter_write")
int handle_tp(void *ctx)
{
 pid_t pid = bpf_get_current_pid_tgid() >> 32;
 if (pid_filter && pid != pid_filter)
  return 0;
 // Outputs to /sys/kernel/debug/tracing/trace_pipe which is shared globally across all eBPF
 // programs.
 // If the output cannot be seen:
 // sudo sh -c 'echo 1 > /sys/kernel/debug/tracing/tracing_on'
 bpf_printk("BPF triggered sys_enter_write from PID %d.\n", pid);

 // Cool stuff happening:
 //   QXcbEventQueue-4144    [005] ...21 121872.317410: bpf_trace_printk: BPF triggered sys_enter_write from PID 4133.
 //   QXcbEventQueue-4143    [036] ...21 121872.317415: bpf_trace_printk: BPF triggered sys_enter_write from PID 4136.
 //          ecli-rs-465014  [019] ...21 121872.317686: bpf_trace_printk: BPF triggered sys_enter_write from PID 464947.
 return 0;
}
