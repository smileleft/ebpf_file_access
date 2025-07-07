// bpf/file_acl.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/types.h>
#include <linux/limits.h> // PATH_MAX


// file path to deny access
const char *target_file = "/tmp/secret.txt";

SEC("tp/syscalls/sys_enter_openat")
int BPF_PROG(file_access_control, int dfd, const char *filename, int flags, umode_t mode) {
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));

    // copy file path from kernel space to user space
    char path[PATH_MAX];
    bpf_probe_read_user(&path, sizeof(path), filename);

    // logging
    bpf_printk("openat called by %s for file %s\n", comm, path);

    // access control logic
    if (bpf_strncmp(path, sizeof(target_file), target_file) == 0) {
        bpf_printk("Blocking access to %s\n", path);
        // -EACCES (Permission denied)
        return -EACCES;
    }

    // permission accepted for another files
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
