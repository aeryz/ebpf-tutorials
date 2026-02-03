#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// The performance difference is real. fentry/fexit programs run about 10x
// faster than kprobes because they use a BPF trampoline mechanism instead
// of the older breakpoint-based approach. If you're building production
// monitoring tools that run on every function call, this matters a lot.

SEC("fentry/do_unlinkat")
int BPF_PROG(do_unlinkat, int dfd, struct filename *name)
{
    pid_t pid;
    pid = bpf_get_current_pid_tgid() >> 32;

    // note that with fentry, we can do name->name
    bpf_printk("fentry: pid = %d, filename = %s\n", pid, name->name);
    return 0;
}

// note that unlike `kretprobe`, we can get the args and the return value
SEC("fexit/do_unlinkat")
int BPF_PROG(do_unlinkat_exit, int dfd, struct filename *name, long ret)
{
    pid_t pid;

    pid = bpf_get_current_pid_tgid() >> 32;
    bpf_printk("fexit: pid = %d, filename = %s, ret = %ld\n", pid, name->name, ret);
    return 0;
}
