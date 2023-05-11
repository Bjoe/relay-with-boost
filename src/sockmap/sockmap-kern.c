#include <stdint.h>

#include "bpf.h"
#include "bpf_helpers.h"
#include <bpf/bpf_endian.h>


//#include <linux/bpf.h>
//#include <linux/bpf_common.h>
//#include <bpf/bpf.h>
//#include <bpf/bpf_helpers.h>

struct bpf_map_def SEC("maps") port_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(int),
    .value_size = sizeof(int),
    .max_entries = 10,
};

struct bpf_map_def SEC("maps") arr_map = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(int),
    .value_size = sizeof(int),
    .max_entries = 1,
};

struct bpf_map_def SEC("maps") sock_map = {
	.type = BPF_MAP_TYPE_SOCKMAP,
	.key_size = sizeof(int),
	.value_size = sizeof(int),
    .max_entries = 10,
};

//#define MIN(a, b) ((a) < (b) ? (a) : (b))
//#define MAX(a, b) ((a) > (b) ? (a) : (b))

#define ptr_to_u64(ptr)    ((__u64)(unsigned long)(ptr))

#ifndef NDEBUG
/* Only use this for debug output. Notice output from bpf_trace_printk()
 * end-up in /sys/kernel/debug/tracing/trace_pipe
 */
#define bpf_debug(fmt, ...)                                                    \
	({                                                                     \
		char ____fmt[] = fmt;                                          \
		bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__);     \
	})
#else
#define bpf_debug(fmt, ...)                                                    \
	{                                                                      \
	}                                                                      \
	while (0)
#endif

#define bpf_printk(fmt, ...)					\
({								\
    char ____fmt[] = fmt;				        \
    bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__);	\
})

SEC("prog_parser")
int _prog_parser(struct __sk_buff *skb)
{
    uint32_t lport = skb->local_port;
    uint32_t rport = bpf_ntohl(skb->remote_port);
    bpf_printk("sockmap: _prog_parser() rport: %d local_port: %d len: %d", rport, lport, skb->len);
	return skb->len;
}

SEC("prog_verdict")
int _prog_verdict(struct __sk_buff *skb)
{
        uint32_t lport = skb->local_port;
        uint32_t rport = bpf_ntohl(skb->remote_port);
        bpf_printk("sockmap: _prog_verdict() lport %d rport %d" , lport, rport);

        //bpf_dump(&port_map, 10);

        int index = 0;
        int* value = bpf_map_lookup_elem(&arr_map, &index);
        bpf_printk("sockmap: _prog_verdict() bpf_map_lookup_elem with index %d -> value %d", index, value);

       // index = 1;
       // int* value = bpf_map_lookup_elem(&arr_map, &index);
       // bpf_printk("sockmap: _prog_verdict() bpf_map_lookup_elem with index %d -> value %d", index, value);

        uint64_t* ret = bpf_map_lookup_elem(&port_map, &lport);
        bpf_printk("sockmap: _prog_verdict() bpf_map_lookup_elem with lport %d -> value %d", lport, ret);
        if(!ret) {
            //ret = bpf_map_lookup_elem(&port_map, &rport);
            bpf_printk("sockmap: _prog_verdict() bpf_map_lookup_elem with rport %d -> value %d", rport, ret);
        }
        int idx = 0; //*ret;
        bpf_printk("sockmap: _prog_verdict() bpf_map_lookup_elem -> idx %d / rport %d or lport %d", idx, rport, lport);
        return bpf_sk_redirect_map(skb, &sock_map, idx, 0);
}
