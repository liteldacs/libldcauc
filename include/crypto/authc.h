//
// Created by 邹嘉旭 on 2024/3/21.
//

#ifndef LDACS_SIM_AUTH_H
#define LDACS_SIM_AUTH_H

#include "secure_core.h"
#include <ld_santilizer.h>

#define AUTHC_ALG_S_LEN 4
#define AUTHC_KLEN_LEN 2
#define SHAREDINFO_LEN 21

extern struct sm_state_s ld_authc_states[];

enum authc_fsm_event_type {
    LD_AUTHC_EV_DEFAULT = 0,
};

enum LD_AUTHC_STATES_E {
    LD_AUTHC_A0 = 0,
    LD_AUTHC_A1,
    LD_AUTHC_A2,
    LD_AUTHC_G0,
    LD_AUTHC_G1,
    LD_AUTHC_G2,
};


enum AUTHC_MACLEN_E {
    AUTHC_MACLEN_INVALID = 0x0,
    AUTHC_MACLEN_96 = 0x1,
    AUTHC_MACLEN_128 = 0x2,
    AUTHC_MACLEN_64 = 0x3,
    AUTHC_MACLEN_256 = 0x4,
};

enum AUTHC_AUTHID_E {
    AUTHC_AUTH_INVALID = 0x0,
    AUTHC_AUTH_SM3HMAC = 0x1,
    AUTHC_AUTH_SM2_WITH_SM3 = 0x2,
};

enum AUTHC_ENC_E {
    AUTHC_ENC_INVALID = 0x0,
    AUTHC_ENC_SM4_CBC = 0x1,
    AUTHC_ENC_SM4_CFB = 0x2,
    AUTHC_ENC_SM4_OFB = 0x3,
    AUTHC_ENC_SM4_ECB = 0x4,
    AUTHC_ENC_SM4_CTR = 0x5,
};

enum AUTHC_KLEN_E {
    AUTHC_KLEN_RESERVED = 0x0,
    AUTHC_KLEN_128 = 0x1,
    AUTHC_KLEN_256 = 0x2,
};

enum PID_E {
    PID_RESERVED = 0x0,
    PID_SIGN = 0x1,
    PID_MAC = 0x2,
    PID_BOTH = 0x3,
};


#pragma pack(1)

typedef struct auc_sharedinfo_s {
    uint8_t MAC_LEN;
    uint8_t AUTH_ID;
    uint8_t ENC_ID;
    uint16_t AS_SAC;
    uint16_t GS_SAC;
    uint8_t K_LEN;
    buffer_t *N_2;
} auc_sharedinfo_t;
#pragma pack()

extern const char *authc_maclen_name[];
extern const char *authc_authid_name[];
extern const char *authc_enc_name[];
extern const char *authc_klen_name[];
extern const char *ld_authc_fsm_states[];
extern const char *s_type_name[];
extern const char *pid_name[];

extern struct_desc_t auc_sharedinfo_desc;

#define get_klen(en)({  \
    int ret;            \
    switch (en){        \
        case AUTHC_KLEN_128:               \
            ret = 16;          \
            break;              \
        case AUTHC_KLEN_256:               \
            ret = 32;          \
            break;              \
        default:                \
            ret = 0;            \
            break;              \
    };                       \
    ret;                       \
})

buffer_t *get_auc_sharedinfo_buf(auc_sharedinfo_t *info);

l_err generate_auc_kdf(ldacs_roles role, buffer_t *random, KEY_HANDLE*key_as_sgw, KEY_HANDLE*key_as_gs,
                       buffer_t **key_as_gs_raw);


#endif //LDACS_SIM_AUTH_H
