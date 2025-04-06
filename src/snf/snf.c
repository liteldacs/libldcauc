//
// Created by 邹嘉旭 on 2025/3/30.
//
#include "snf.h"
#include "crypto/authc.h"
#include "crypto/key.h"


snf_obj_t snf_obj = {
    .PROTOCOL_VER = PROTECT_VERSION,
    // .GS_SAC = 0xABD,
    .net_opt = {
    },
    .is_merged = TRUE
};

int8_t init_as_snf_layer() {
    snf_obj.snf_emap = init_enode_map();
    snf_obj.role = LD_AS;
    return LDCAUC_OK;
}

int8_t init_gs_snf_layer(uint16_t GS_SAC, char *gsnf_addr, uint16_t gsnf_port) {
    snf_obj.snf_emap = init_enode_map();
    snf_obj.role = LD_GS;
    snf_obj.GS_SAC = GS_SAC;

    memcpy(snf_obj.net_opt.addr, gsnf_addr, GEN_ADDRLEN);
    snf_obj.net_opt.port = gsnf_port;

    snf_obj.is_merged = TRUE;

    return LDCAUC_OK;
}

int8_t init_gs_snf_layer_unmerged(uint16_t GS_SAC, char *gsnf_addr, uint16_t gsnf_port) {
    init_gs_snf_layer(GS_SAC, gsnf_addr, gsnf_port);

    snf_obj.is_merged = FALSE;

    return LDCAUC_OK;
}

int8_t destory_snf_layer() {
    hashmap_free(snf_obj.snf_emap);
    return LDCAUC_OK;
}

static snf_entity_t *init_snf_en(snf_args_t *args) {
    snf_entity_t *snf_en = calloc(1, sizeof(snf_entity_t));

    uint8_t role = args->role;
    snf_en->AS_SAC = args->AS_SAC;
    snf_en->GS_UA = args->AS_CURR_GS_SAC;
    snf_en->AS_UA = args->AS_UA;
    snf_en->AS_CURR_GS_SAC = args->AS_CURR_GS_SAC;

    snf_en->AUTHC_MACLEN = AUTHC_MACLEN_256; /* default mac len is 256  */
    snf_en->AUTHC_AUTH_ID = AUTHC_AUTH_SM3HMAC;
    snf_en->AUTHC_ENC_ID = AUTHC_ENC_SM4_CBC;
    snf_en->AUTHC_KLEN = AUTHC_KLEN_128;

    snf_en->shared_random = NULL;
    snf_en->key_as_gs_b = NULL;

    UA_STR(ua_as);
    UA_STR(ua_sgw);
    if (role == ROLE_AS) {
        key_get_handle(LD_AS, get_ua_str(snf_en->AS_UA, ua_as), get_ua_str(snf_en->GS_UA, ua_sgw), ROOT_KEY,
                       &snf_en->key_as_sgw_r_h);
    } else if (role == ROLE_SGW) {
        snf_en->key_as_gs_b = init_buffer_unptr();
        key_get_handle(LD_SGW, get_ua_str(snf_en->GS_UA, ua_as), get_ua_str(snf_en->AS_UA, ua_sgw), ROOT_KEY,
                       &snf_en->key_as_sgw_r_h);
    }


    stateM_init(&snf_en->auth_fsm, &ld_authc_states[role == ROLE_AS ? LD_AUTHC_A0 : LD_AUTHC_G0], NULL);

    snf_en->gs_conn = NULL;
    snf_en->gs_finish_auth = FALSE;
    snf_en->gsnf_count = 0;

    return snf_en;
}

int8_t clear_snf_en(snf_entity_t *snf_en) {
    if (snf_en == NULL) return LDCAUC_NULL;
    if (snf_en->shared_random != NULL) { free_buffer(snf_en->shared_random); }
    if (snf_en->key_as_gs_b != NULL) { free_buffer(snf_en->key_as_gs_b); }

#ifdef UNUSE_CRYCARD
    if (snf_en->key_as_sgw_r_h != NULL) { free_buffer(snf_en->key_as_sgw_r_h); }
    if (snf_en->key_as_sgw_s_h != NULL) { free_buffer(snf_en->key_as_sgw_s_h); }
    if (snf_en->key_as_gs_h != NULL) { free_buffer(snf_en->key_as_gs_h); }
    if (snf_en->key_session_en_h != NULL) { free_buffer(snf_en->key_session_en_h); }
    if (snf_en->key_session_mac_h != NULL) { free_buffer(snf_en->key_session_mac_h); }
#endif
    free(snf_en);
    return LDCAUC_OK;
}

// typedef void (*completion_cb)(void *user_data, int result);
//
// void lib_entry(completion_cb cb, void *user_data);

int8_t entry_LME_AUTH(void *args) {
    snf_args_t *snf_args = (snf_args_t *) args;
    snf_obj.as_snf_en = init_snf_en(snf_args);
    l_err err;

    if ((err = change_state(&snf_obj.as_snf_en->auth_fsm, LD_AUTHC_EV_DEFAULT,
                            &(fsm_event_data_t){
                                &ld_authc_fsm_events[LD_AUTHC_A1], snf_obj.as_snf_en
                            }))) {
        log_error("cant change state correctly, %d", err);
        return LDCAUC_INTERNAL_ERROR;
    }
    return LDCAUC_OK;
}

int8_t exit_LME_AUTH(void *args) {
    return LDCAUC_OK;
}

int8_t register_snf_en(snf_args_t *snf_args) {
    if (snf_args->AS_SAC >= 4096 || snf_args->AS_CURR_GS_SAC >= 4096) return LDCAUC_WRONG_PARA;
    snf_entity_t *en = init_snf_en(snf_args);
    if (en == NULL) {
        return LDCAUC_NULL;
    }
    set_enode(en);

    // TODO: DLS OPEN CALLBACK

    return LDCAUC_OK;
}

int8_t unregister_snf_en(uint16_t SAC) {
    return delete_enode_by_sac(SAC, clear_snf_en);
}

static void free_snf_en(snf_entity_t *en) {
    clear_snf_en(en);
    free(en);
}


