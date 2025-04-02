//
// Created by 邹嘉旭 on 2025/3/30.
//
#include "snf.h"
#include "crypto/authc.h"
#include "crypto/key.h"

static struct hashmap *init_enode_map();

static const void *set_enode(snf_entity_t *en);

static int8_t delete_enode_by_sac(uint16_t as_sac, int8_t (*clear_func)(snf_entity_t *snf_en));

snf_obj_t snf_obj = {
};

int8_t init_snf_layer(int8_t role) {
    snf_obj.snf_emap = init_enode_map();
    return LDCAUC_OK;
}

int8_t destory_snf_layer() {
    hashmap_free(snf_obj.snf_emap);
    return LDCAUC_OK;
}

static snf_entity_t *init_snf_en(uint8_t role, snf_args_t *args) {
    snf_entity_t *snf_en = calloc(1, sizeof(snf_entity_t));

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
        key_get_handle(role, get_ua_str(snf_en->AS_UA, ua_as), get_ua_str(snf_en->GS_UA, ua_sgw), ROOT_KEY,
                       &snf_en->key_as_sgw_r_h);
    } else if (role == ROLE_SGW) {
        snf_en->key_as_gs_b = init_buffer_unptr();
        key_get_handle(role, get_ua_str(snf_en->GS_UA, ua_as), get_ua_str(snf_en->AS_UA, ua_sgw), ROOT_KEY,
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

int8_t entry_LME_AUTH(void *args) {
    snf_args_t *snf_args = (snf_args_t *) args;
    snf_obj.as_snf_en = init_snf_en(ROLE_AS, snf_args);
    return LDCAUC_OK;
}

int8_t register_snf_entity(snf_args_t *snf_args) {
    if (snf_args->AS_SAC >= 4096 || snf_args->AS_CURR_GS_SAC >= 4096) return LDCAUC_WRONG_PARA;
    snf_entity_t *en = init_snf_en(ROLE_SGW, snf_args);
    if (en == NULL) {
        return LDCAUC_NULL;
    }
    set_enode(en);

    return LDCAUC_OK;
}

int8_t unregister_snf_entity(uint16_t SAC) {
    return delete_enode_by_sac(SAC, clear_snf_en);
}

static snf_entity_t *init_snpsub_entity(uint16_t SAC) {
    snf_entity_t *en = (snf_entity_t *) calloc(1, sizeof(snf_entity_t));
    en->AS_SAC = SAC;

    return en;
}

static void free_snpsub_entity(snf_entity_t *en) {
    free(en);
}


static uint64_t hash_enode(const void *item, uint64_t seed0, uint64_t seed1) {
    const snf_entity_t *node = item;
    return hashmap_sip(&node->AS_SAC, sizeof(uint16_t), seed0, seed1);
}

static snf_entity_t *get_enode(const uint16_t as_sac) {
    return hashmap_get(snf_obj.snf_emap, &(snf_entity_t){
                           .AS_SAC = as_sac,
                       });
}

static bool has_enode(const uint16_t as_sac) {
    return hashmap_get(snf_obj.snf_emap, &(snf_entity_t){
                           .AS_SAC = as_sac,
                       }) != NULL;
}

static struct hashmap *init_enode_map() {
    return hashmap_new(sizeof(snf_entity_t), 0, 0, 0,
                       hash_enode, NULL, NULL, NULL);
}

static const void *set_enode(snf_entity_t *en) {
    const void *ret = hashmap_set(snf_obj.snf_emap, en);

    free_snpsub_entity(en);

    return ret;
}

static int8_t delete_enode_by_sac(uint16_t as_sac, int8_t (*clear_func)(snf_entity_t *snf_en)) {
    snf_entity_t *en = get_enode(as_sac);
    if (en) {
        if (clear_func) {
            clear_func(en);
        }
        hashmap_delete(snf_obj.snf_emap, en);
        return LDCAUC_OK;
    }
    return LDCAUC_NULL;
}
