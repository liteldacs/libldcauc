//
// Created by 邹嘉旭 on 2024/11/9.
//

#ifndef GS_CONN_H
#define GS_CONN_H
#include <ld_net.h>
#include <ld_hashmap.h>

typedef struct gs_propt_s {
    basic_conn_t bc;
} gs_propt_t;

typedef struct gs_propt_node_s {
    gs_propt_t *propt;
    uint16_t GS_SAC;
} gs_propt_node_t;


typedef struct gs_conn_define_s {
    char *addr;
    int port;
    uint16_t GS_SAC;
} gs_conn_define_t;

typedef struct gs_conn_service_s {
    gs_conn_define_t conn_defines[10];
    struct hashmap *conn_map;

    net_ctx_t net_ctx;
    //SGW
    pthread_t service_th;
    gs_propt_t *sgw_conn; // GS -> SGW
} gs_conn_service_t;

extern gs_conn_service_t gs_conn_service;

l_err init_client_gs_conn_service(char *remote_addr, int remote_port, int local_port,
                                  l_err (*recv_handler)(basic_conn_t *));

l_err init_server_gs_conn_service(int listen_port);

bool send_gs_pkt(basic_conn_t *bc);

bool reset_gs_conn(basic_conn_t *bc);

void gs_conn_close(basic_conn_t *bc);

l_err gs_conn_accept(net_ctx_t *ctx);

void *gs_conn_connect(net_ctx_t *ctx, char *remote_addr, int remote_port, int local_port);

gs_propt_node_t *get_conn_enode(const uint16_t gs_sac);


#endif //GS_CONN_H
