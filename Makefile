CC = go

obj := bpf_x86_bpfel.o bpf_x86_bpfel.go
src := bpf/main.bpf.c main.go
header := bpf/vmlinux.h
out := go-net-trace
deps := go.sum

PHONY: all clean header deps obj

clean:
	rm -f $(obj) $(out) $(header) $(deps)

header:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(header)

deps:
	$(CC) get $(out)

obj:
	$(CC) generate

all: deps header obj
	$(CC) build $(out)
	chmod +x $(out)
