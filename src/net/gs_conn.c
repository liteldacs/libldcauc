//
// Created by 邹嘉旭 on 2024/11/9.
//


#include <ldcauc.h>

#include "net/gs_conn.h"
#include "net/net.h"


gs_tcp_propt_t *init_gs_conn(int role, net_opt_t *net_opt) {
    gs_tcp_propt_t *gs_conn = malloc(sizeof(gs_tcp_propt_t));

    if (init_basic_conn(gs_conn, net_opt, role) == FALSE) {
        return NULL;
    }

    return gs_conn;
}

bool send_gs_pkt(basic_conn_t **bcp) {
    // gs_tcp_propt_t *mlt_ld = (gs_tcp_propt_t *) bcp;
    // CLONE_TO_CHUNK(mlt_ld->bc->write_pkt, mlt_ld->tpacket.ptr, mlt_ld->tpacket.len)
    return TRUE;
}

static bool gs_conn_accept(net_opt_t *net_opt) {
    gs_tcp_propt_t *gs_conn;
    if ((gs_conn = init_gs_conn(LD_SGW, net_opt)) == NULL) {
        log_error("Cannot initialize connection!");
        return FALSE;
    }
    return TRUE;
}

bool reset_gs_conn(basic_conn_t **bcp) {
    gs_tcp_propt_t *mlt_ld = (gs_tcp_propt_t *) bcp;
    return TRUE;
}

void close_gs_conn(basic_conn_t **bcp) {
    gs_tcp_propt_t *mlt_ld = (gs_tcp_propt_t *) bcp;
    log_warn("Closing connection!");
}

void *gs_epoll_setup(void *args) {
    int nfds;
    int i;
    net_opt_t *net_opt = args;
    while (TRUE) {
        nfds = core_epoll_wait(epoll_fd, epoll_events, MAX_EVENTS, 20);

        if (nfds == ERROR) {
            // if not caused by signal, cannot recover
            ERR_ON(errno != EINTR, "core_epoll_wait");
        }

        /* processing ready fd one by one */
        for (i = 0; i < nfds; i++) {
            struct epoll_event *curr_event = epoll_events + i;
            int fd = *((int *) (curr_event->data.ptr));

            if (fd == net_opt->server_fd) {
                gs_conn_accept(net_opt); /* never happened in GS */
            } else {
                basic_conn_t **bcp = curr_event->data.ptr;
                int status;
                assert(bcp != NULL);

                if (connecion_is_expired(bcp))
                    continue;

                if (curr_event->events & EPOLLIN) {
                    //recv
                    status = request_handle(bcp);
                }
                if (curr_event->events & EPOLLOUT) {
                    //send
                    status = response_handle(bcp);
                }

                if (status == ERROR)
                    connecion_set_expired(bcp);
                else {
                    connecion_set_reactivated(bcp);
                }
            }
        }
        server_connection_prune();
    }
    close(epoll_fd);
    server_shutdown(net_opt->server_fd);
}

