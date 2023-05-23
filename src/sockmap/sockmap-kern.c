#include <stdint.h>

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(key_size, sizeof(int));
  __uint(value_size, sizeof(int));
  __uint(max_entries, 10);
} port_map SEC("maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(key_size, sizeof(int));
  __uint(value_size, sizeof(int));
  __uint(max_entries, 1);
} arr_map SEC("maps");

struct {
  __uint(type, BPF_MAP_TYPE_SOCKMAP);
  __uint(key_size, sizeof(int));
  __uint(value_size, sizeof(int));
  __uint(max_entries, 10);
} sock_map SEC("maps");

#define ptr_to_u64(ptr)    ((__u64)(unsigned long)(ptr))

SEC("prog_parser")
int _prog_parser(struct __sk_buff *skb)
{
    uint32_t lport = skb->local_port;
    uint32_t rport = bpf_ntohl(skb->remote_port);
    //bpf_printk("sockmap: _prog_parser() rport: %d local_port: %d len: %d", rport, lport, skb->len);
	return skb->len;
}

SEC("prog_verdict")
int _prog_verdict(struct __sk_buff *skb)
{
        uint32_t lport = skb->local_port;
        uint32_t rport = bpf_ntohl(skb->remote_port);
        //bpf_printk("sockmap: _prog_verdict() lport %d rport %d" , lport, rport);

        //bpf_dump(&port_map, 10);

        int index = 0;
        int* value = bpf_map_lookup_elem(&arr_map, &index);
        //bpf_printk("sockmap: _prog_verdict() bpf_map_lookup_elem with index %d -> value %d", index, value);

       // index = 1;
       // int* value = bpf_map_lookup_elem(&arr_map, &index);
       // bpf_printk("sockmap: _prog_verdict() bpf_map_lookup_elem with index %d -> value %d", index, value);

        uint64_t* ret = bpf_map_lookup_elem(&port_map, &lport);
        //bpf_printk("sockmap: _prog_verdict() bpf_map_lookup_elem with lport %d -> value %d", lport, ret);
        if(!ret) {
            //ret = bpf_map_lookup_elem(&port_map, &rport);
            //bpf_printk("sockmap: _prog_verdict() bpf_map_lookup_elem with rport %d -> value %d", rport, ret);
        }
        int idx = 0; //*ret;
        //bpf_printk("sockmap: _prog_verdict() bpf_map_lookup_elem -> idx %d / rport %d or lport %d", idx, rport, lport);
        return bpf_sk_redirect_map(skb, &sock_map, idx, 0);
}
