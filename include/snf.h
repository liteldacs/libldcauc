//
// Created by 邹嘉旭 on 2025/3/30.
//

#ifndef SNF_H
#define SNF_H

#include <ld_statemachine.h>
#include <ld_buffer.h>
#include "ldcauc.h"
#include "net/gs_conn.h"


typedef struct snf_entity_s {
    uint32_t AS_UA;
    uint32_t GS_UA;
    uint16_t AS_SAC;
    uint16_t AS_CURR_GS_SAC; /* current connected/to connect GS SAC for AS */

    uint8_t AUTHC_MACLEN,
            AUTHC_AUTH_ID,
            AUTHC_ENC_ID,
            AUTHC_KLEN;
    sm_statemachine_t auth_fsm;
    buffer_t *shared_random;
    void *key_as_sgw_r_h;
    void *key_as_sgw_s_h;
    buffer_t *key_as_gs_b;
    void *key_as_gs_h;
    void *key_session_en_h;
    void *key_session_mac_h;

    //for GS
    bool gs_finish_auth;
    /* for SGW */
    gs_tcp_propt_t *gs_conn; // SGW -> GS

    /* for GSC */
    uint32_t gsnf_count;
} snf_entity_t;

typedef struct snf_obj_s {
    struct hashmap *snf_emap;
    snf_entity_t *as_snf_en;
    int8_t role;
} snf_obj_t;

extern snf_obj_t snf_obj;

typedef struct snf_args_s {
    uint16_t AS_SAC;
    uint32_t AS_UA;
    uint16_t AS_CURR_GS_SAC;
} snf_args_t;

int8_t init_snf_layer(int8_t role);

int8_t clear_snf_en(snf_entity_t *snf_en);

int8_t destory_snf_layer();

int8_t entry_LME_AUTH(void *args);

int8_t register_snf_entity(snf_args_t *snf_args);

int8_t unregister_snf_entity(uint16_t SAC);


#endif //SNF_H
