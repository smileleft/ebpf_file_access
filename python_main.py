# python_main.py
import os
import sys
import signal
from bcc import BPF
from bcc.libbcc import _get_dev_path_fd_by_path # for bpf_printk

# eBPF C source code path
BPF_PROGRAM = "bpf/file_acl.c"

def main():
    print("Loading eBPF program...")

    try:
        # BPF program load
        b = BPF(src_file=BPF_PROGRAM, debug=0)

        # connect to tracepoint of sys_enter_openat
        # name of BPF program should be identical to SEC("tp/syscalls/sys_enter_openat") of C code
        b.attach_tracepoint(tp="syscalls:sys_enter_openat", fn_name="file_access_control")

        print("eBPF program loaded and attached to sys_enter_openat tracepoint.")
        print("Attempt to access '/tmp/secret.txt' now. It should be blocked.")
        print("Press Ctrl+C to exit and unload the eBPF program.")

        # print bpf_printk message
        def print_bpf_printk():
            trace_fd = _get_dev_path_fd_by_path("/sys/kernel/debug/tracing/trace_pipe")
            if trace_fd < 0:
                print("Error: Could not open trace_pipe. Try 'sudo mount -t debugfs none /sys/kernel/debug'")
                return

            with os.fdopen(trace_fd, "r") as f:
                while True:
                    try:
                        line = f.readline()
                        if line:
                            # check message of bpf_printk
                            if "Blocking access" in line or "openat called" in line:
                                print(f"[BPF_PRINTK] {line.strip()}")
                    except KeyboardInterrupt:
                        break # terminate with Ctrl+C


        # signal handler Ctrl+C
        def signal_handler(signum, frame):
            print("\nUnloading eBPF program.")
            sys.exit(0)

        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

        signal.pause()

    except Exception as e:
        print(f"Error loading/attaching eBPF program: {e}")
        print("Make sure you are running as root and necessary kernel headers are installed.")
        print("Also ensure debugfs is mounted: sudo mount -t debugfs none /sys/kernel/debug")
        sys.exit(1)

if __name__ == "__main__":
    main()
