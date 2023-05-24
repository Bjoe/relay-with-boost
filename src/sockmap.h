#ifndef SOCKMAP_H
#define SOCKMAP_H

#include "sockmap.skel.h"

struct sockmap {
    int sock_map{};
    int sock_last_index{};
    int ip_map{};
    int port_last_index{};
    uint max_keys = 10;
    sockmap_bpf* skel{};
};

#endif // SOCKMAP_H
