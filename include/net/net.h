//
// Created by jiaxv on 23-7-9.
//

#ifndef TEST_CLIENT_CLIENT_H
#define TEST_CLIENT_CLIENT_H
#include  "ld_config.h"

#define IPV6_ADDRLEN 128
# define DEFAULT_FD -1

struct role_propt {
    ldacs_roles l_r;
    sock_roles s_r;

    int (*server_make)(uint16_t port);

    int (*init_handler)(basic_conn_t *);
};


const struct role_propt *get_role_propt(int role);

int server_entity_setup();

// extern int client_shutdown();

extern int server_shutdown();


int write_packet(basic_conn_t *bc);

int read_first_packet(basic_conn_t *bc, int pre_fd);


int first_request_handle(basic_conn_t *bc, int pre_fd);

extern int request_handle(basic_conn_t **bc);

extern int response_handle(basic_conn_t **bc);

int request_forward(basic_conn_t **bcp);

#endif //TEST_CLIENT_CLIENT_H
