#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

// IMPORTANT:
// Global variables in eBPF are stored in the data section of your compiled program.
// When you load the eBPF program into the kernel, these variables get their initial values.
// The neat part is that user-space can modify these values before the program starts running,
// effectively passing configuration parameters into your kernel code.

// - `volatile` tells the compiler that user-space can modify it before loading the program
// - When pid_target is 0, the program captures openat calls from all processes.
// If you set it to a specific PID, it only monitors that process. 
/// @description "Process ID to trace"
const volatile int pid_target = 0;

SEC("tp/syscalls/sys_enter_openat")
int tracepoint__syscalls__sys_enter_openat(struct trace_event_raw_sys_enter* ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;

    if (pid_target && pid_target != pid)
        return false;

    // Use bpf_printk to print the process information
    bpf_printk("Process ID: %d enter sys openat\n", pid);
    return 0;
}

/// "Trace open family syscalls."
char LICENSE[] SEC("license") = "GPL";
