//
// Created by jiaxv on 23-7-9.
//

#ifndef TEST_CLIENT_CLIENT_EPOLL_H
#define TEST_CLIENT_CLIENT_EPOLL_H

#include "net/connection.h"


int net_epoll_add(int e_fd, basic_conn_t *conn_opt, uint32_t events,
                  struct epoll_event *pev);

void net_epoll_out(int e_fd, basic_conn_t *bc);

void net_epoll_in(int e_fd, basic_conn_t *bc);

// void net_epoll_out2(int e_fd, basic_conn_t *bc);

#endif //TEST_CLIENT_CLIENT_EPOLL_H
