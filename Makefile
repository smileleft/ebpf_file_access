# Makefile
.PHONY: all run clean

PYTHON_APP := python_main.py
BPF_C_SOURCE := bpf/file_acl.c

all: run

run:
	sudo python3 ${PYTHON_APP}

clean:
	rm -f /tmp/secret.txt # remove test file
