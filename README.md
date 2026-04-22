# go-net-trace: eBPF Process Network Analyzer

A lightweight network traffic analyzer built with **Go** and **eBPF**. `go-net-trace` monitors network activity and attributes bandwidth usage to specific Process IDs (PIDs) in real-time.

## Features

* **Kernel-level Monitoring:** Uses eBPF kprobes for high-efficiency data collection.
* **Process Attribution:** Maps network packets to the originating process.

## eBPF probes

This script uses:

* `tcp_sendmsg` and `udp_sendmsg` for outgoing traffic.
* `tcp_recvmsg` and `udp_recvmsg` for incoming traffic.

## How to's

### build ebpf vmlinux.h

```bash
bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h
```

### install dependencies

```bash
go get go-net-trace
```

### generate ebpf object file

```bash
go generate
```

### build and run

```bash
go build -o go-net-trace
chmod +x go-net-trace
sudo ./go-net-trace
```

......or if you are lazy like myself, just run:

```bash
make all
```

and then execute it with:

```bash
sudo ./go-net-trace
```
