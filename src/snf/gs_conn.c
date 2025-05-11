//
// Created by 邹嘉旭 on 2024/11/9.
//

#include "gs_conn.h"
#include <ld_config.h>
#include "snf.h"

l_err init_conn_enode_map(struct hashmap **map);

l_err set_conn_enode(gs_propt_node_t *en);

l_err delete_conn_enode(uint16_t gs_sac, int8_t (*clear_func)(gs_propt_node_t *en));

l_err delete_conn_enode_by_connptr(gs_propt_t *ptr, int8_t (*clear_func)(gs_propt_node_t *en));

gs_conn_service_t gs_conn_service = {
    .conn_defines = {
        {"127.0.0.1", 55560, 4000},
        // {"127.0.0.1", 55560, 4001},
        {NULL, 0, 0}
    },
};

static l_err init_basic_gs_conn_service() {
    l_err err;
    if ((err = init_conn_enode_map(&gs_conn_service.conn_map)) != LD_OK) {
        return err;
    }
    return LD_OK;
}


l_err init_client_gs_conn_service(char *remote_addr, int remote_port, int local_port,
                                  l_err (*recv_handler)(basic_conn_t *)) {
    l_err err;
    if ((err = init_basic_gs_conn_service()) != LD_OK) {
        return err;
    }

    gs_conn_service.net_ctx = (net_ctx_t){
        .conn_handler = gs_conn_connect,
        .recv_handler = recv_handler,
        .close_handler = gs_conn_close,
        .send_handler = defalut_send_pkt,
        .epoll_fd = core_epoll_create(0, -1),
    };

    gs_conn_service.sgw_conn = client_entity_setup(&gs_conn_service.net_ctx, remote_addr, remote_port, local_port);
    pthread_create(&gs_conn_service.service_th, NULL, net_setup, &gs_conn_service.net_ctx);
    pthread_detach(gs_conn_service.service_th);
    return LD_OK;
}

l_err init_server_gs_conn_service(int listen_port) {
    l_err err;
    if ((err = init_basic_gs_conn_service()) != LD_OK) {
        return err;
    }
    gs_conn_service.net_ctx = (net_ctx_t){
        .recv_handler = recv_gsnf,
        .close_handler = gs_conn_close,
        .accept_handler = gs_conn_accept,
        .send_handler = defalut_send_pkt,
        .epoll_fd = core_epoll_create(0, -1),
    };
    init_heap_desc(&gs_conn_service.net_ctx.hd_conns);
    server_entity_setup(listen_port, &gs_conn_service.net_ctx,
                        snf_obj.is_merged == TRUE ? LD_TCPV6_SERVER : LD_TCP_SERVER);
    pthread_create(&gs_conn_service.service_th, NULL, net_setup, &gs_conn_service.net_ctx);
    pthread_join(gs_conn_service.service_th, NULL);
    return LD_OK;
}


bool send_gs_pkt(basic_conn_t *bcp) {
    return TRUE;
}

void *gs_conn_connect(net_ctx_t *ctx, char *remote_addr, int remote_port, int local_port) {
    gs_propt_t *gs_conn = malloc(sizeof(gs_propt_t));

    gs_conn->bc.remote_addr = strdup(remote_addr);
    gs_conn->bc.remote_port = remote_port;
    gs_conn->bc.local_port = local_port;

    if (init_basic_conn(&gs_conn->bc, ctx, snf_obj.is_merged ? LD_TCPV6_CLIENT : LD_TCP_CLIENT) == FALSE) {
        return NULL;
    }

    return gs_conn;
}


l_err gs_conn_accept(net_ctx_t *ctx) {
    gs_propt_t *gs_conn = malloc(sizeof(gs_propt_t));

    if (init_basic_conn(&gs_conn->bc, ctx, LD_TCP_SERVER) == FALSE) {
        log_error("Cannot initialize connection!");
        free(gs_conn);
        return LD_ERR_INTERNAL;
    }

    int client_port = ntohs(((struct sockaddr_in *) &gs_conn->bc.saddr)->sin_port);

    for (int i = 0; gs_conn_service.conn_defines[i].addr != NULL; i++) {
        if (client_port == gs_conn_service.conn_defines[i].port) {
            gs_propt_node_t *node = calloc(1, sizeof(gs_propt_node_t));
            node->propt = gs_conn;
            node->GS_SAC = gs_conn_service.conn_defines[i].GS_SAC;
            if (set_conn_enode(node) != LD_OK) {
                return LD_ERR_NULL;
            }
            return LD_OK;
        }
    }

    log_warn("Not available GS connection from port `%d`!", client_port);
    return LD_ERR_INTERNAL;
}


bool reset_gs_conn(basic_conn_t *bc) {
    gs_propt_t *mlt_ld = (gs_propt_t *) bc;
    return TRUE;
}

void gs_conn_close(basic_conn_t *bc) {
    gs_propt_t *gs_conn = (gs_propt_t *) bc;
    if (!gs_conn) return;
    delete_conn_enode_by_connptr(gs_conn, NULL);
    free(gs_conn);
    log_warn("Closing connection!");
}


uint64_t hash_conn_enode(const void *item, uint64_t seed0, uint64_t seed1) {
    const gs_propt_node_t *node = item;
    return hashmap_sip(&node->GS_SAC, sizeof(uint16_t), seed0, seed1);
}

l_err init_conn_enode_map(struct hashmap **map) {
    *map = hashmap_new(sizeof(gs_propt_node_t), 0, 0, 0,
                       hash_conn_enode, NULL, NULL, NULL);
    if (!*map) return LD_ERR_NULL;
    return LD_OK;
}

l_err set_conn_enode(gs_propt_node_t *en) {
    if (!en) return LD_ERR_NULL;

    const void *ret = hashmap_set(gs_conn_service.conn_map, en);
    /* !!!Do not free the previous entity !!! */
    free(en);
    return LD_OK;
}

gs_propt_node_t *get_conn_enode(const uint16_t gs_sac) {
    return hashmap_get(gs_conn_service.conn_map, &(gs_propt_node_t){
                           .GS_SAC = gs_sac
                       });
}

gs_propt_node_t *get_conn_enode_by_ptr(gs_propt_t *ptr) {
    size_t iter = 0;
    void *item;
    while (hashmap_iter(gs_conn_service.conn_map, &iter, &item)) {
        gs_propt_node_t *node = item;
        if (node->propt == ptr)
            return node;
    }
    return NULL;
}


bool has_conn_enode(const uint16_t gs_sac) {
    return hashmap_get(gs_conn_service.conn_map, &(gs_propt_node_t){
                           .GS_SAC = gs_sac,
                       }) != NULL;
}

l_err delete_conn_enode(uint16_t gs_sac, int8_t (*clear_func)(gs_propt_node_t *en)) {
    gs_propt_node_t *en = get_conn_enode(gs_sac);
    if (en) {
        if (clear_func) {
            clear_func(en);
        }
        hashmap_delete(gs_conn_service.conn_map, en);
        return LD_OK;
    }
    return LD_ERR_INTERNAL;
}

l_err delete_conn_enode_by_connptr(gs_propt_t *ptr, int8_t (*clear_func)(gs_propt_node_t *en)) {
    gs_propt_node_t *en = get_conn_enode_by_ptr(ptr);
    if (en) {
        if (clear_func) {
            clear_func(en);
        }
        hashmap_delete(gs_conn_service.conn_map, en);
        return LD_OK;
    }
    return LD_ERR_INTERNAL;
}
