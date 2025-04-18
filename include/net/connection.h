//
// Created by jiaxv on 23-7-9.
//

#ifndef TEST_CLIENT_CONNECTION_H
#define TEST_CLIENT_CONNECTION_H

#include <ld_log.h>
#include <ld_heap.h>
#include <ld_epoll.h>
#include <passert.h>
#include <ld_mqueue.h>
#include "net/net_core.h"

extern heap_desc_t hd_conns;

typedef struct basic_conn_s {
    int fd; /* connection_s fd */
    struct epoll_event event; /* epoll event */
    struct sockaddr_storage saddr; /* IP socket address */
    buffer_t read_pkt; /* Receive packet */
    // buffer_t write_pkt; /* Transmit packet */
    lfqueue_t *write_pkts;
    bool trans_done;
    const struct role_propt *rp;
    const struct net_opt_s *opt;
} basic_conn_t;

typedef struct net_opt_s {
    char name[32];
    ldacs_roles role;
    int server_fd; //for GSW
    char addr[GEN_ADDRLEN];
    int port;
    int timeout;

    void (*close_handler)(basic_conn_t *);

    bool (*reset_conn)(basic_conn_t *);

    l_err (*recv_handler)(basic_conn_t *);

    l_err (*send_handler)(basic_conn_t *);
} net_opt_t;


bool init_basic_conn(basic_conn_t *bc, const net_opt_t *opt, int role);

bool connecion_is_expired(basic_conn_t *bcp, int timeout);

void connection_close(basic_conn_t *bc);

void connecion_set_reactivated(basic_conn_t *bdp);

void connecion_set_expired(basic_conn_t *bcp);

void server_connection_prune(int timeout);


#endif //TEST_CLIENT_CONNECTION_H
