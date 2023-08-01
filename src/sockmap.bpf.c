#include "vmlinux.h" // Generated via: bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
//#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "sockmap.bpf.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
  __uint(type, BPF_MAP_TYPE_SOCKHASH);
  __uint(max_entries, 10);
  __type(key, struct socket_key);
  __type(value, __u64);
} sock_hash_rx SEC(".maps");

SEC("sk_skb/stream_parser")
int bpf_prog_parser(struct __sk_buff *skb)
{
  __u64 ip = bpf_ntohl(skb->remote_ip4);
  __u32 port = bpf_ntohl(skb->remote_port);
  bpf_printk("sockmap: _prog_parser() ip: %lu port: %i len: %i", ip, port, skb->len);
  return skb->len;
}

static inline
  void extract_socket_key(struct __sk_buff *skb, struct socket_key *key)
{
  key->src_ip = bpf_ntohl(skb->remote_ip4);
  key->dst_ip = bpf_ntohl(skb->local_ip4);
  key->src_port = (bpf_htonl(skb->remote_port));
  key->dst_port = skb->local_port;

  bpf_printk("sockhash: extract_socket_key() remote_ip4 %lu remote_port %i", key->src_ip, key->src_port);
  bpf_printk("sockhash: extract_socket_key() local ip4 %lu local_port %i", key->dst_ip, key->dst_port);
}

SEC("sk_skb/stream_verdict")
int bpf_prog_verdict(struct __sk_buff *skb)
{
  struct socket_key key;

  extract_socket_key(skb, &key);

  int result = bpf_sk_redirect_hash(skb, &sock_hash_rx, &key, 0);
  bpf_printk("sockhash: bpf_prog_verdict() bpf_sk_redirect_map() -> %i", result);
  return result;
}
