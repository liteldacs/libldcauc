//
// Created by 邹嘉旭 on 2024/3/21.
//

#ifndef LDACS_SIM_SECURE_CORE_H
#define LDACS_SIM_SECURE_CORE_H


#include <ldacs_sim.h>
#include <ldacs_utils.h>
#include <key_manage.h>


#define S_TYP_LEN 8
#define VER_LEN 3
#define PID_LEN 2
#define KEY_TYPE_LEN 4
#define NCC_LEN 16
#define NONCE_LEN 128 >> 3

#define BASE_PATH "/.ldcauc/"
#define ROOT_KEY_BIN_PATH "/keystore/"

#define AS_DB_NAME "as_sql.db"
#define GS_DB_NAME "gs_sql.db"
#define SGW_DB_NAME "sgw_sql.db"
#define AS_KEY_TABLE "as_keystore"
#define GS_KEY_TABLE "gs_keystore"
#define SGW_KEY_TABLE "sgw_keystore"
#define ROOT_KEY_LEN 16
#define DEFAULT_VALIDATE 365


#define get_sec_maclen(en)({    \
    int ret;                    \
    switch(en){                 \
        case 0x1:               \
            ret = 12;          \
            break;              \
        case 0x2:               \
            ret = 16;          \
            break;              \
        case 0x3:               \
            ret = 8;          \
            break;              \
        case 0x4:               \
            ret = 32;          \
            break;              \
        default:                \
            ret = 0;            \
            break;              \
    };                          \
    ret;        \
})


void generate_rand(uint8_t *rand, size_t len);

/* generate a rand int, max size is 64bits (8 bytes) */
uint64_t generate_urand(size_t rand_bits_sz);

/* generate a unlimit rand array */
void generate_nrand(uint8_t *rand, size_t sz);

#endif //LDACS_SIM_SECURE_CORE_H
