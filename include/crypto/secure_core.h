//
// Created by 邹嘉旭 on 2024/3/21.
//

#ifndef LDACS_SIM_SECURE_CORE_H
#define LDACS_SIM_SECURE_CORE_H

#define PROTECT_VERSION 1

#include <ldacs_sim.h>
#include <ldacs_utils.h>
#include <key_manage.h>


#define S_TYP_LEN 8
#define VER_LEN 3
#define PID_LEN 2
#define KEY_TYPE_LEN 4
#define NCC_LEN 16
#define NONCE_LEN 128 >> 3

//#define KEY_DB_NAME "/root/ldacs/stack_new/ldacs_stack/resources/ld_sql.db"
//#define KEY_DB_NAME "/root/ldacs/ldacs_sim_sgw/resources/ld_sql.db"
#define AS_DB_NAME "/root/ldacs/stack_new/ldacs_stack/resources/as_sql.db"
#define GS_DB_NAME "/root/ldacs/stack_new/ldacs_stack/resources/gs_sql.db"
#define SGW_DB_NAME "/root/ldacs/stack_new/ldacs_stack/resources/sgw_sql.db"
#define AS_KEY_TABLE "as_keystore"
#define GS_KEY_TABLE "gs_keystore"
#define SGW_KEY_TABLE "sgw_keystore"
#define ROOT_KEY_LEN 16
#define DEFAULT_VALIDATE 365
//#define KEY_BIN_PATH  "/root/ldacs/stack_new/ldacs_stack/resources/keystore/rootkey.bin"
#define KEY_BIN_PATH  "/root/ldacs/ldacs_sim_sgw/resources/keystore/rootkey.bin"
//
// enum p_sec {
//     AES_CMAC,
//     SM3_HMAC,
// };

enum SEC_ALG_MACLEN {
    SEC_MACLEN_INVAILD = 0x0,
    SEC_MACLEN_96 = 0x1,
    SEC_MACLEN_128 = 0x2,
    SEC_MACLEN_64 = 0x3,
    SEC_MACLEN_256 = 0x4,
};

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


/* TODO: 处理一下和km_src的关系 */
void generate_rand(uint8_t *rand, size_t len);

/* generate a rand int, max size is 64bits (8 bytes) */
uint64_t generate_urand(size_t rand_bits_sz);

/* generate a unlimit rand array */
void generate_nrand(uint8_t *rand, size_t sz);
#endif //LDACS_SIM_SECURE_CORE_H
