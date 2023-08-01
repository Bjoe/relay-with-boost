#ifndef SOCKMAP_BPF_H
#define SOCKMAP_BPF_H

// DO NOT INCLUDE vmlinux.h OR sockmap.skel.h HEADER HERE

struct socket_key {
  __u32 src_ip;
  __u32 dst_ip;
  __u32 src_port;
  __u32 dst_port;
};

#endif // SOCKMAP_BPF_H
