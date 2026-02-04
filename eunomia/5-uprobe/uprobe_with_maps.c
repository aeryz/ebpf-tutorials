#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define TASK_COMM_LEN 16
#define MAX_LINE_SIZE 80

#define MAX_ENTRIES 10240
#define TASK_COMM_LEN 16

struct event {
  unsigned int pid;
  const char *param;
  char comm[TASK_COMM_LEN];
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_ENTRIES);
  __type(key, __u32);
  __type(value, struct event);
} values SEC(".maps");

// // to see some functions of bash:
// // nm -n `which bash` | grep " T " | less
SEC("uretprobe//nix/store/f15k3dpilmiyv6zgpib289rnjykgr1r4-bash-5.3p9/bin/"
    "bash:read_builtin")
int BPF_KRETPROBE(read_builtin_exit, long ret) {
  char comm[TASK_COMM_LEN];
  char str[MAX_LINE_SIZE];
  u32 pid;
  struct event *eventp;

  if (ret) {
    return 0;
  }

  pid = bpf_get_current_pid_tgid() >> 32;
  
  eventp = bpf_map_lookup_elem(&values, &pid);
  if (!eventp) {
    bpf_printk("could not find the event, exiting..");
    return 0;
  }

  if (!eventp->param) {
    bpf_printk("param is not set");
    return 0;
  }
  
  bpf_probe_read_user_str(str, sizeof(str), eventp->param);

  const void *param = eventp->param;
  bpf_printk("seems like all worked: %s, %p", str, param);

  return 0;
};

SEC("uprobe//nix/store/f15k3dpilmiyv6zgpib289rnjykgr1r4-bash-5.3p9/bin/"
    "bash:bind_variable")
int BPF_KPROBE(bind_var_entry, const char *name, const char* value, int flags) {
  char comm[TASK_COMM_LEN];
  char n[MAX_LINE_SIZE];
  char v[MAX_LINE_SIZE];
  u32 pid;
  struct event event = {};

  // if (!name || !value) {
  //   return 0;
  // }

  pid = bpf_get_current_pid_tgid() >> 32;
  event.pid = pid;
  event.param = name;

  bpf_probe_read_user_str(n, sizeof(n), name);
  bpf_probe_read_user_str(v, sizeof(v), value);

  if (n[0] == 'x' && n[1] == '\0') {
    bpf_printk("PID %d read: %s", pid, v);
  }

  bpf_map_update_elem(&values, &pid, &event, BPF_ANY);

  return 0;
};

char LICENSE[] SEC("license") = "GPL";
