#ifndef __EXECSNOOP_H
#define __EXECSNOOP_H

#include <stdbool.h>

#define TASK_COMM_LEN 80

struct event {
    int pid;
    int ppid;
    int uid;
    long int retval;
    bool is_exit;
    char comm[TASK_COMM_LEN];
    bool omg;
};

#endif /* __EXECSNOOP_H */
