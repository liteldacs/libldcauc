//
// Created by 邹嘉旭 on 2024/11/9.
//

#ifndef GS_CONN_H
#define GS_CONN_H
#include "net/connection.h"

typedef struct gs_tcp_propt_s {
    basic_conn_t bc;
    const struct proto_opt *opt;
} gs_tcp_propt_t;

struct shared_key_temp {
    int32_t uas;
    uint8_t key[4];
};

extern const struct shared_key_temp shared_keys[];


// gs_tcp_propt_t *init_gs_conn(int role);
gs_tcp_propt_t *init_gs_conn(int role, net_opt_t *net_opt);

bool recv_gs_pkt(basic_conn_t *bc);

bool send_gs_pkt(basic_conn_t *bc);

bool forward_gs_pkt(basic_conn_t *bc);

bool reset_gs_conn(basic_conn_t *bc);

void close_gs_conn(basic_conn_t *bc);

void *gs_epoll_setup(void *args);
#endif //GS_CONN_H
