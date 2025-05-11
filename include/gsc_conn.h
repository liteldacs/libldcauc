//
// Created by 邹嘉旭 on 2024/11/9.
//

#ifndef GSC_CONN_H
#define GSC_CONN_H
#include <ld_net.h>
#include <ld_hashmap.h>

typedef struct gsc_propt_s {
    basic_conn_t bc;
} gsc_propt_t;

// typedef struct gsc_propt_node_s {
//     gsc_propt_t *propt;
//     uint16_t GS_SAC;
// } gsc_propt_node_t;


// typedef struct gsc_conn_define_s {
//     char *addr;
//     int port;
//     uint16_t GS_SAC;
// } gs_conn_define_t;

/* 当前默认GSC只有一个，且该服务不需要考虑客户端 */
typedef struct gsc_conn_service_s {
    // gs_conn_define_t conn_defines[10];
    // struct hashmap *conn_map;
    /* 先默认只有一个GSC */
    gsc_propt_t *gsc_conn;

    net_ctx_t net_ctx;
    //SGW
    pthread_t service_th;
    // gs_propt_t *sgw_conn; // GS -> SGW
} gsc_conn_service_t;

extern gsc_conn_service_t gsc_conn_service;

l_err init_server_gsc_conn_service(int listen_port);

bool send_gsc_pkt(basic_conn_t *bc);

bool reset_gsc_conn(basic_conn_t *bc);

void gsc_conn_close(basic_conn_t *bc);

l_err gsc_conn_accept(net_ctx_t *ctx);

// void *gsc_conn_connect(net_ctx_t *ctx, char *remote_addr, int remote_port, int local_port);

gsc_propt_t *get_gsc_conn(const uint16_t gs_sac);


#endif //GSC_CONN_H
