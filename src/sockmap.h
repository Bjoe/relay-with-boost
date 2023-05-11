#ifndef SOCKMAP_H
#define SOCKMAP_H

struct sockmap {
    int sock_map{};
    int sock_last_index{};
    int port_map{};
    int port_last_index{};
    int arr_map{};
    int arr_last_index{};
    int max_keys = 10;
};

#endif // SOCKMAP_H
