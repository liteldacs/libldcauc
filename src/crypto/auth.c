//
// Created by 邹嘉旭 on 2025/4/1.
//
//
// Created by 邹嘉旭 on 2025/3/7.
//
//
// Created by 邹嘉旭 on 2024/3/21.
//
#include <ld_statemachine.h>
#include <ld_buffer.h>
#include <ld_santilizer.h>
#include "crypto/authc.h"
#include "crypto/key.h"
#include "snp_sub.h"
#include "snf.h"


struct sm_state_s ld_authc_states[] = {
        {
                .data = "LD_AUTHC_A0",
                .entryAction = &sm_default_entry_action,
                .exitAction = &sm_default_exit_action,
                .transitions = (sm_transition_t[]) {
                        {
                                LD_AUTHC_EV_DEFAULT, (void *) "LD_AUTHC_A1", &default_guard, NULL,
                                &ld_authc_states[LD_AUTHC_A1]
                        },
                },
                .numTransitions = 1,
        },
        {
                .data = "LD_AUTHC_A1",
                .entryAction = &sm_default_entry_action,
                .exitAction = &sm_default_exit_action,
                .transitions = (sm_transition_t[]) {
                        {LD_AUTHC_EV_DEFAULT, (void *) "LD_AUTHC_A2", &default_guard, NULL, &ld_authc_states[LD_AUTHC_A2]},
                        {LD_AUTHC_EV_DEFAULT, (void *) "LD_AUTHC_A0", &default_guard, NULL, &ld_authc_states[LD_AUTHC_A0]},
                },
                .numTransitions = 2,
        },
        {
                .data = "LD_AUTHC_A2",
                .entryAction = &sm_default_entry_action,
                .exitAction = &sm_default_exit_action,
                .transitions = (sm_transition_t[]) {
                        {
                                LD_AUTHC_EV_DEFAULT, (void *) "LD_AUTHC_A0", &default_guard, NULL,
                                &ld_authc_states[LD_AUTHC_A0]
                        },
                },
                .numTransitions = 1,
        },
        {
                .data = "LD_AUTHC_G0",
                .entryAction = &sm_default_entry_action,
                .exitAction = &sm_default_exit_action,
                .transitions = (sm_transition_t[]) {
                        {
                                LD_AUTHC_EV_DEFAULT, (void *) "LD_AUTHC_G1", &default_guard, NULL,
                                &ld_authc_states[LD_AUTHC_G1]
                        },
                },
                .numTransitions = 1,
        },
        {
                .data = "LD_AUTHC_G1",
                .entryAction = &sm_default_entry_action,
                .exitAction = &sm_default_exit_action,
                .transitions = (sm_transition_t[]) {
                        {LD_AUTHC_EV_DEFAULT, (void *) "LD_AUTHC_G2", &default_guard, NULL, &ld_authc_states[LD_AUTHC_G2]},
                        {LD_AUTHC_EV_DEFAULT, (void *) "LD_AUTHC_G0", &default_guard, NULL, &ld_authc_states[LD_AUTHC_G0]},
                },
                .numTransitions = 2,
        },
        {
                .data = "LD_AUTHC_G2",
                .entryAction = &sm_default_entry_action,
                .exitAction = &sm_default_exit_action,
                .transitions = (sm_transition_t[]) {
                        {
                                LD_AUTHC_EV_DEFAULT, (void *) "LD_AUTHC_G0", &default_guard, NULL,
                                &ld_authc_states[LD_AUTHC_G0]
                        },
                },
                .numTransitions = 1,
        },
};
const char *authc_maclen_name[] = {
        "AUTHC_MACLEN_INVALID",
        "AUTHC_MACLEN_96",
        "AUTHC_MACLEN_128",
        "AUTHC_MACLEN_64",
        "AUTHC_MACLEN_256",
};

const char *authc_authid_name[] = {
        "AUTHC_AUTH_INVALID",
        "AUTHC_AUTH_SM3HMAC",
        "AUTHC_AUTH_SM2_WITH_SM3",
};

const char *authc_enc_name[] = {
        "AUTHC_ENC_INVALID",
        "AUTHC_ENC_SM4_CBC",
        "AUTHC_ENC_SM4_CFB",
        "AUTHC_ENC_SM4_OFB",
        "AUTHC_ENC_SM4_ECB",
        "AUTHC_ENC_SM4_CTR",
};

const char *authc_klen_name[] = {
        "AUTHC_KLEN_RESERVED",
        "AUTHC_KLEN_128",
        "AUTHC_KLEN_256",
};

const char *ld_authc_fsm_states[] = {
        "LD_AUTHC_A0",
        "LD_AUTHC_A1",
        "LD_AUTHC_A2",
        "LD_AUTHC_G0",
        "LD_AUTHC_G1",
        "LD_AUTHC_G2",
};
const char *s_type_name[] = {
        "AUC_RQST",
        "AUC_RESP",
        "AUC_KEY_EXC",
        "KEY_UPD_RQST",
        "KEY_UPD_RESP",
        "G_KEY_UPD_ACK",

        "SN_SESSION_EST_RQST",
        "SN_SESSION_EST_RESP",
};
const char *pid_name[] = {
        "PID_RESERVED",
        "PID_SIGN",
        "PID_MAC",
        "PID_BOTH",
};


static enum_names authc_maclen_names = {AUTHC_MACLEN_INVALID, AUTHC_MACLEN_256, authc_maclen_name, NULL};
static enum_names authc_auth_names = {AUTHC_AUTH_INVALID, AUTHC_AUTH_SM2_WITH_SM3, authc_authid_name, NULL};
static enum_names authc_enc_names = {AUTHC_ENC_INVALID, AUTHC_ENC_SM4_CTR, authc_enc_name, NULL};
static enum_names authc_klen_names = {AUTHC_KLEN_128, AUTHC_KLEN_256, authc_klen_name, NULL};

/**
 * Sharedinfo
 */
static field_desc auc_sharedinfo_fields[] = {
        {ft_enum, AUTHC_ALG_S_LEN, "MAC_LEN", &authc_maclen_names},
        {ft_enum, AUTHC_ALG_S_LEN, "AUTH_ID", &authc_auth_names},
        {ft_enum, AUTHC_ALG_S_LEN, "ENC_ID",  &authc_enc_names},
        {ft_set,  SAC_LEN,         "AS_SAC", NULL},
        {ft_set,  SAC_LEN,         "GS_SAC", NULL},
        {ft_enum, AUTHC_KLEN_LEN,  "KLEN",    &authc_klen_names},
        {ft_pad,    0,             "PAD",    NULL},
        {ft_fl_str, 0,             "N2",      &(pk_fix_length_t) {.len = NONCE_LEN}},
        {ft_end,    0, NULL,                 NULL},
};
struct_desc_t auc_sharedinfo_desc = {"AUC_SHAREDINFO", auc_sharedinfo_fields};

buffer_t *get_auc_sharedinfo_buf(auc_sharedinfo_t *info) {
    buffer_t *info_buf = init_buffer_unptr();
    pb_stream pbs;
    zero(&pbs);
    uint8_t res_str[32] = {0};

    init_pbs(&pbs, res_str, 32, "SHAREDINFO");
    if (!out_struct(info, &auc_sharedinfo_desc, &pbs, NULL)) {
        free_buffer(info_buf);
        return NULL;
    }
    close_output_pbs(&pbs);
    CLONE_TO_CHUNK(*info_buf, pbs.start, pbs_offset(&pbs))
    return info_buf;
}

l_err
generate_auc_kdf(ldacs_roles role, buffer_t *random, void **key_as_sgw, void **key_as_gs, buffer_t **key_as_gs_raw,
                 uint16_t AS_UA, uint16_t GS_FLAG) {
    UA_STR(ua_as);
    UA_STR(ua_gs);
    UA_STR(ua_sgw);
    get_ua_str(AS_UA, ua_as);
    get_ua_str(GS_FLAG, ua_gs);
    get_ua_str(DFT_SGW_UA, ua_sgw);

    switch (role) {
        case LD_AS:
            as_derive_keys(random->ptr, random->len, ua_as, ua_gs, ua_sgw, key_as_sgw, key_as_gs);
            break;
        case LD_SGW:
            sgw_derive_keys(random->ptr, random->len, ua_as, ua_gs, ua_sgw, key_as_sgw, key_as_gs_raw);
            break;
        default:
            return LD_ERR_WRONG_PARA;
    }
    return LD_OK;
}
