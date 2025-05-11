//
// Created by 邹嘉旭 on 2024/11/9.
//

#include "gsc_conn.h"
#include <ld_config.h>
#include "snf.h"
gsc_conn_service_t gsc_conn_service = {
};

static l_err init_basic_gsc_conn_service() {
    l_err err;
    return LD_OK;
}

l_err init_server_gsc_conn_service(int listen_port) {
    l_err err;
    gsc_conn_service.net_ctx = (net_ctx_t){
        .recv_handler = recv_gsnf,
        .close_handler = gsc_conn_close,
        .accept_handler = gsc_conn_accept,
        .send_handler = defalut_send_pkt,
        .epoll_fd = core_epoll_create(0, -1),
    };
    init_heap_desc(&gsc_conn_service.net_ctx.hd_conns);
    server_entity_setup(listen_port, &gsc_conn_service.net_ctx,
                        LD_TCPV6_SERVER);
    pthread_create(&gsc_conn_service.service_th, NULL, net_setup, &gsc_conn_service.net_ctx);
    pthread_join(gsc_conn_service.service_th, NULL);
    return LD_OK;
}


bool send_gsc_pkt(basic_conn_t *bcp) {
    return TRUE;
}

l_err gsc_conn_accept(net_ctx_t *ctx) {
    if (gsc_conn_service.gsc_conn) return LD_ERR_INTERNAL;
    gsc_conn_service.gsc_conn = malloc(sizeof(gsc_propt_t));

    if (init_basic_conn(&gsc_conn_service.gsc_conn->bc, ctx, LD_TCPV6_SERVER) == FALSE) {
        log_error("Cannot initialize connection!");
        free(gsc_conn_service.gsc_conn);
        return LD_ERR_INTERNAL;
    }

    return LD_OK;
}


bool reset_gsc_conn(basic_conn_t *bc) {
    gsc_propt_t *mlt_ld = (gsc_propt_t *) bc;
    return TRUE;
}

void gsc_conn_close(basic_conn_t *bc) {
    gsc_propt_t *gsc_conn = (gsc_propt_t *) bc;
    if (!gsc_conn) return;
    free(gsc_conn);
    gsc_conn_service.gsc_conn = NULL;
    log_warn("Closing connection!");
}

gsc_propt_t *get_gsc_conn(const uint16_t gs_sac) {
    return gsc_conn_service.gsc_conn;
}
