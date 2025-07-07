// main.go
package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall" bpf_file_acl bpf/file_acl.c -- -I./bpf/

func main() {
	// rlimit control: remove memory limit for eBPF map and program
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memlock rlimit: %v", err)
	}

	// bpf_file_acl object loading
	// It is defined in bpf_file_acl.go
	objs := bpf_file_aclObjects{}
	if err := loadBpf_file_aclObjects(&objs, nil); err != nil {
		log.Fatalf("Loading eBPF objects failed: %v", err)
	}
	defer objs.Close() // eBPF object cleaning

	// eBPF program connection on sys_enter_openat 
	tp, err := link.Tracepoint("syscalls", "sys_enter_openat", objs.FileAccessControl)
	if err != nil {
		log.Fatalf("Linking tracepoint failed: %v", err)
	}
	defer tp.Close() // link close

	log.Println("eBPF program loaded and attached to sys_enter_openat tracepoint.")
	log.Printf("Attempt to access '/tmp/secret.txt' now. It should be blocked.")
	log.Println("Press Ctrl+C to exit and unload the eBPF program.")

	// waiting CTRL+C
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	log.Println("Unloading eBPF program.")
}
