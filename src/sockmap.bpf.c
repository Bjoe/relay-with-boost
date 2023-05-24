#include "vmlinux.h" // Generated via: bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
//#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";


struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);
    __type(value, int);
    __uint(max_entries, 1024);
} ip_map SEC(".maps");


struct {
  __uint(type, BPF_MAP_TYPE_SOCKMAP);
  __type(key, int);
  __type(value, int);
  __uint(max_entries, 10);
} sock_map SEC(".maps");

SEC("sk_skb/stream_parser")
int _prog_parser(struct __sk_buff *skb)
{
      __u64 ip = bpf_ntohl(skb->remote_ip4);
      __u32 port = bpf_ntohl(skb->remote_port);
    bpf_printk("sockmap: _prog_parser() ip: %lu port: %i len: %i", ip, port, skb->len);
	return skb->len;
}

SEC("sk_skb/stream_verdict")
int _prog_verdict(struct __sk_buff *skb)
{
    __u64 ip = bpf_ntohl(skb->remote_ip4);
    __u32 port = bpf_ntohl(skb->remote_port);
    __u64 key = ((ip << 32) | port);

    bpf_printk("sockmap: _prog_verdict() remote_ip4 %lu remote_port %i", ip, port);
    bpf_printk("sockmap: _prog_verdict() key %lu", key);
    int *idx = bpf_map_lookup_elem(&ip_map, &key);
    if (!idx) {
        return SK_DROP;
    }
    bpf_printk("sockmap: _prog_verdict() bpf_map_lookup_elem with key %lu -> value %i", key, *idx);
    return bpf_sk_redirect_map(skb, &sock_map, *idx, 0);
}
