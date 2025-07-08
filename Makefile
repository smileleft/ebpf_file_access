# Makefile
.PHONY: all build clean run

C_SOURCES := bpf/file_acl.c
GO_SOURCES := main.go

all: build

build: bpf_file_acl.go
go build -o file-access-control ${GO_SOURCES}

bpf_file_acl.go: ${C_SOURCES}
go generate ./...

clean:
rm -f file-access-control bpf_file_acl.go bpf_file_acl_bpfel.o bpf_file_acl_bpfel_xgo.o
rm -rf bpf/
rm -rf go.sum go.mod

run: build
sudo ./file-access-control
