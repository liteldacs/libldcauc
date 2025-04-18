//
// Created by jiaxv on 23-7-9.
//

#include <netdb.h>
#include <net/gs_conn.h>

#include "net/net_core.h"
#include <netinet/tcp.h>

heap_desc_t hd_conns;

static inline void connection_set_nodelay(basic_conn_t *bc) {
    static int enable = 1;
    setsockopt(bc->fd, IPPROTO_TCP, TCP_NODELAY, &enable, sizeof(enable));
}


bool connecion_is_expired(basic_conn_t *bc, int timeout) {
    heap_t *conn_hp = get_heap(&hd_conns, bc);
    int64_t active_time = conn_hp->factor;
    return timeout ? (time(NULL) - active_time > timeout) : FALSE;
}

void connecion_set_reactivated(basic_conn_t *bc) {
    heap_t *conn_hp = get_heap(&hd_conns, bc);
    if (!conn_hp) return;
    conn_hp->factor = time(NULL); /* active_time */
    if (bc->rp->s_r & 1) heap_bubble_down(&hd_conns, conn_hp->heap_idx);
}

void connecion_set_expired(basic_conn_t *bc) {
    heap_t *conn_hp = get_heap(&hd_conns, bc);
    if (!conn_hp) return;
    conn_hp->factor = 0; // very old time
    if (bc->rp->s_r & 1) heap_bubble_up(&hd_conns, conn_hp->heap_idx);
}

int connection_register(basic_conn_t *bcp, int64_t factor) {
    if (hd_conns.heap_size >= MAX_HEAP) {
        return ERROR;
    }
    return heap_insert(&hd_conns, bcp, factor);
}

void connection_unregister(basic_conn_t *bc) {
    assert(hd_conns.heap_size >= 1);

    heap_t *conn_hp = get_heap(&hd_conns, bc);
    int heap_idx = conn_hp->heap_idx;
    hd_conns.hps[heap_idx] = hd_conns.hps[hd_conns.heap_size - 1];
    hd_conns.hps[heap_idx]->heap_idx = heap_idx;
    hd_conns.heap_size--;

    fprintf(stderr, "HEAP SIZE: %d\n", hd_conns.heap_size);
    heap_bubble_down(&hd_conns, heap_idx);
}


#define ADDR_LEN (64/BITS_PER_BYTE)

/**
 * Store the basic_conn_t addresses into the propts in large end mode
 * @param start the start address of propts struct
 * @param addr address of basic_conn_t
 */
static void set_basic_conn_addr(uint8_t *start, void *addr) {
    uint64_t addr_int = (uint64_t) addr;
    for (size_t i = 0; i < ADDR_LEN; i++) {
        start[i] = (uint8_t) (addr_int >> (BITS_PER_BYTE * i));
    }
}


/**
 *
 * @param conn_opt
 * @param opt
 * @param handler
 * @param role
 * @return
 */
bool init_basic_conn(basic_conn_t *bc, const net_opt_t *opt, int role) {
    // basic_conn_t *bc = malloc(sizeof(basic_conn_t));
    // set_basic_conn_addr(conn_opt, bc);

    do {
        bc->fd = 0;
        bc->opt = opt;
        bc->rp = get_role_propt(role);
        bc->fd = bc->rp->init_handler(bc);

        if (bc->fd == ERROR) {
            break;
        }

        ABORT_ON((epoll_fd = core_epoll_create(0, epoll_fd)) == ERROR, "core_epoll_create");

        if (connection_register(bc, time(NULL)) == ERROR) break;
        net_epoll_add(epoll_fd, bc, EPOLLIN | EPOLLET, &bc->event);
        set_fd_nonblocking(bc->fd);
        connection_set_nodelay(bc);

        zero(&bc->read_pkt);
        bc->write_pkts = lfqueue_init();

        return TRUE;
    } while (0);

    // opt->close_conn(conn_opt);
    connection_close(bc);
    return FALSE;
}


/* close connection, free memory */
void connection_close(basic_conn_t *bc) {
    passert(bc != NULL);
    ABORT_ON(bc->fd == ERROR, "FD ERROR");

    if (bc->opt->close_handler) bc->opt->close_handler(bc);

    core_epoll_del(epoll_fd, bc->fd, 0, NULL);
    if (close(bc->fd) == ERROR) {
        log_info("The remote has closed, EXIT!");
        //raise(SIGINT); /* terminal, send signal */
    }

    connection_unregister(bc);
}

void server_connection_prune(int timeout) {
    while (hd_conns.heap_size > 0 && timeout) {
        basic_conn_t *bc = hd_conns.hps[0]->obj;
        int64_t active_time = hd_conns.hps[0]->factor;
        if (time(NULL) - active_time >= timeout) {
            log_info("prune %p %d\n", bc, hd_conns.heap_size);
            connection_close(bc);
        } else
            break;
    }
}
