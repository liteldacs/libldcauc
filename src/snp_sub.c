//
// Created by 邹嘉旭 on 2025/3/28.
//
#include <ld_log.h>
#include "snf.h"
#include "crypto/authc.h"
#include "snp_sub.h"
#include "crypto/cipher.h"

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
    snf_entity_t *as_man = snf_obj.role == LD_AS ? snf_obj.as_snf_en : (snf_entity_t *) get_enode(AS_SAC);
    return as_man->key_as_gs_h;
}

static KEY_HANDLE get_enc_key(uint16_t AS_SAC) {
    snf_entity_t *as_man = snf_obj.role == LD_AS ? snf_obj.as_snf_en : (snf_entity_t *) get_enode(AS_SAC);
    return as_man->key_as_gs_h;
}

int8_t snpsub_crypto(uint16_t AS_SAC, uint8_t *in, size_t in_len, uint8_t *out, size_t *out_len, bool is_encrypt) {
    if (!in || in_len == 0 || !out) return LDCAUC_WRONG_PARA;
    if (!is_finish_auth(AS_SAC)) {
        memcpy(out, in, in_len);
        *out_len = in_len;
        return LDCAUC_OK;
    }
    if (is_encrypt) {
        return encrypt_uint8(get_enc_key(AS_SAC), in, in_len, out, out_len) == LD_OK
                   ? LDCAUC_OK
                   : LDCAUC_INTERNAL_ERROR;
    } else {
        return decrypt_uint8(get_enc_key(AS_SAC), in, in_len, out, out_len) == LD_OK
                   ? LDCAUC_OK
                   : LDCAUC_INTERNAL_ERROR;
    }
}

int8_t snpsub_calc_hmac(uint16_t AS_SAC, uint8_t SEC, uint8_t *in, size_t in_len, uint8_t *out, size_t *out_len) {
    if (!in || in_len == 0 || !out) return LDCAUC_WRONG_PARA;

    *out_len = get_sec_maclen(SEC);
    if (!is_finish_auth(AS_SAC)) {
        memcpy(out, zero_mac, get_sec_maclen(SEC));
        return LDCAUC_OK;
    }
    calc_hmac_uint(in, in_len, get_hmac_key(AS_SAC), out, *out_len);

    return LDCAUC_OK;
}

int8_t snpsub_vfy_hmac(uint16_t AS_SAC, uint8_t SEC, uint8_t *snp_pdu, size_t pdu_len) {
    if (!snp_pdu || pdu_len == 0) return LDCAUC_WRONG_PARA;
    if (!is_finish_auth(AS_SAC)) return LDCAUC_OK;

    size_t mac_len = get_sec_maclen(SEC);
    size_t to_vfy_len = pdu_len - get_sec_maclen(SEC);

    if (verify_hmac_uint(get_hmac_key(AS_SAC), snp_pdu + to_vfy_len, snp_pdu, to_vfy_len, mac_len)) {
        return LDCAUC_OK;
    } else {
        return LDCAUC_FAIL;
    }
}
