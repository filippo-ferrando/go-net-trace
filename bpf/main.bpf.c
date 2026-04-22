// eBPF hooks to tcp_sendmsg and udp_sendmsg to capture outgoing packets and
// send them to go userspace via perf events.

typedef unsigned char __u8;
typedef short unsigned int __u16;
typedef unsigned int __u32;
typedef long long unsigned int __u64;
typedef int __s32;

#include "vmlinux.h"

#define bpf_stream_vprintk bpf_stream_printk_local

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#undef bpf_stream_vprintk

char LICENSE[] SEC("license") = "GPL";

struct traffic_stats {
  __u64 rx_udp_bytes;
  __u64 rx_tcp_bytes;
  __u64 tx_udp_bytes;
  __u64 tx_tcp_bytes;
};

// store byte per PID
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 10240);
  __type(key, __u32);                  // store PID as key
  __type(value, struct traffic_stats); // store byte sent as value
} proc_traffic SEC(".maps");

static __always_inline void update_stats(__u32 pid, __u64 len, bool tx,
                                         bool tcp) {
  if (pid == 0)
    return;
  struct traffic_stats *stats = bpf_map_lookup_elem(&proc_traffic, &pid);
  if (stats) {
    if (tx && tcp)
      __sync_fetch_and_add(&stats->tx_tcp_bytes, len);
    else if (tx && !tcp)
      __sync_fetch_and_add(&stats->tx_udp_bytes, len);
    else if (!tx && tcp)
      __sync_fetch_and_add(&stats->rx_tcp_bytes, len);
    else
      __sync_fetch_and_add(&stats->rx_udp_bytes, len);
  } else {
    struct traffic_stats new_stats = {0};
    if (tx, tcp)
      new_stats.tx_tcp_bytes = len;
    else if (tx, !tcp)
      new_stats.tx_udp_bytes = len;
    else if (!tx, tcp)
      new_stats.rx_tcp_bytes = len;
    else
      new_stats.rx_udp_bytes = len;
    bpf_map_update_elem(&proc_traffic, &pid, &new_stats, BPF_ANY);
  }
}

SEC("kprobe/tcp_sendmsg")
int kprobe_tcp_sendmsg(struct pt_regs *ctx) {
  __u32 pid = bpf_get_current_pid_tgid() >> 32;
  size_t size = (size_t)PT_REGS_PARM3(ctx);
  update_stats(pid, size, true, true);
  return 0;
}

SEC("kprobe/tcp_recvmsg")
int kprobe_tcp_recvmsg(struct pt_regs *ctx) {
  __u32 pid = bpf_get_current_pid_tgid() >> 32;
  size_t len = (size_t)PT_REGS_PARM3(ctx);
  update_stats(pid, len, false, true);
  return 0;
}

SEC("kprobe/udp_sendmsg")
int kprobe_udp_sendmsg(struct pt_regs *ctx) {
  __u32 pid = bpf_get_current_pid_tgid() >> 32;
  size_t len = (size_t)PT_REGS_PARM3(ctx);
  update_stats(pid, len, true, false);
  return 0;
}

SEC("kprobe/udp_recvmsg")
int kprobe_udp_recvmsg(struct pt_regs *ctx) {
  __u32 pid = bpf_get_current_pid_tgid() >> 32;
  size_t len = (size_t)PT_REGS_PARM3(ctx);
  update_stats(pid, len, false, false);
  return 0;
}
