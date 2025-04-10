//
// Created by 邹嘉旭 on 2025/3/28.
//
#include "snp_sub.h"

#include <ld_config.h>
#include <ld_log.h>
#include <snf.h>
#include <crypto/authc.h>

static bool is_finish_auth(uint16_t AS_SAC) {
    snf_entity_t *snf_en = snf_obj.role == LD_AS
                           ? snf_obj.as_snf_en
                           : (snf_entity_t *) get_enode(AS_SAC);
    switch (snf_obj.role) {
        case LD_AS:
        case LD_SGW: {
            const char *authc_str = snf_obj.role == LD_AS
                                    ? ld_authc_fsm_states[LD_AUTHC_A2]
                                    : ld_authc_fsm_states[LD_AUTHC_G2];
            return in_state(&snf_en->auth_fsm, authc_str);
        }
        case LD_GS: {
            return snf_en->gs_finish_auth;
        }
        default: {
            return FALSE;
        }
    }
}

const char *zero_mac[32] = {0};

static KEY_HANDLE get_hmac_key(uint16_t AS_SAC) {
    snf_entity_t *as_man = config.role == LD_AS ? snf_obj.as_snf_en : (snf_entity_t *) get_enode(AS_SAC);
    return as_man->key_as_gs_h;
}

int8_t snpsub_crypto(uint16_t AS_SAC, char *in, size_t in_len, char *out, size_t *out_len, bool is_encrypt) {
    if (is_encrypt) {

    } else {

    }
    return LDCAUC_OK;
}

int8_t snpsub_calc_hmac(uint16_t AS_SAC, uint8_t SEC, char *in, size_t in_len, char *out, size_t *out_len) {

    if (!in || in_len == 0 || !out) return LDCAUC_WRONG_PARA;

    if (!is_finish_auth(AS_SAC)) {
        memcpy(out, zero_mac, get_sec_maclen(SEC));
        *out_len = get_sec_maclen(SEC);
        return LDCAUC_OK;
    }

    return LDCAUC_OK;
}

int8_t snpsub_vfy_hmac(uint16_t AS_SAC, uint8_t SEC, char *in, size_t in_len, char *mac, size_t mac_len) {
    if (!in || in_len == 0) return LDCAUC_WRONG_PARA;
    if (!is_finish_auth(AS_SAC)) return LDCAUC_OK;

    return LDCAUC_OK;
}
