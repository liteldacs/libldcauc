//
// Created by 邹嘉旭 on 2025/3/30.
//
#include "snf.h"

#include "crypto/authc.h"
#include "crypto/key.h"


snf_obj_t snf_obj = {
        .PROTOCOL_VER = PROTECT_VERSION,
        .is_merged = TRUE
};

int8_t init_as_snf_layer(finish_auth finish_auth, trans_snp trans_snp) {
    snf_obj.snf_emap = init_enode_map();
    snf_obj.role = LD_AS;

    snf_obj.finish_auth_func = finish_auth;
    snf_obj.trans_snp_func = trans_snp;
    return LDCAUC_OK;
}

int8_t init_gs_snf_layer(uint16_t GS_SAC, const char *gsnf_addr, uint16_t gsnf_port,
                         trans_snp trans_snp) {
    snf_obj.snf_emap = init_enode_map();
    snf_obj.role = LD_GS;
    snf_obj.GS_SAC = GS_SAC;

    snf_obj.trans_snp_func = trans_snp;

    memcpy(snf_obj.net_opt.addr, gsnf_addr, GEN_ADDRLEN);
    snf_obj.net_opt.port = gsnf_port;
    snf_obj.net_opt.recv_handler = config.is_merged ? recv_gsg : recv_gsnf;
    snf_obj.sgw_conn = init_gs_conn(LD_GS, &snf_obj.net_opt);

    pthread_create(&snf_obj.client_th, NULL, gs_epoll_setup, &snf_obj.net_opt);
    pthread_detach(snf_obj.client_th);

    snf_obj.is_merged = TRUE;

    return LDCAUC_OK;
}


int8_t init_gs_snf_layer_unmerged(uint16_t GS_SAC, const char *gsnf_addr, uint16_t gsnf_port,
                                  trans_snp trans_snp) {
    init_gs_snf_layer(GS_SAC, gsnf_addr, gsnf_port, trans_snp);

    snf_obj.is_merged = FALSE;

    return LDCAUC_OK;
}

int8_t init_sgw_snf_layer(uint16_t listen_port) {
    snf_obj.snf_emap = init_enode_map();
    snf_obj.role = LD_SGW;

    init_heap_desc(&hd_conns);
    snf_obj.net_opt.server_fd = server_entity_setup(LD_SGW, listen_port);
    snf_obj.net_opt.recv_handler = recv_gsnf;

    log_info("SGW server successfully started.");
    gs_epoll_setup(&snf_obj.net_opt);

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
    snf_en->SGW_UA = args->SGW_SAC;
    snf_en->AS_UA = args->AS_UA;
    snf_en->AS_CURR_GS_SAC = args->SGW_SAC;

    snf_en->AUTHC_MACLEN = AUTHC_MACLEN_256; /* default mac len is 256  */
    snf_en->AUTHC_AUTH_ID = AUTHC_AUTH_SM3HMAC;
    snf_en->AUTHC_ENC_ID = AUTHC_ENC_SM4_CBC;
    snf_en->AUTHC_KLEN = AUTHC_KLEN_128;

    snf_en->shared_random = NULL;
    snf_en->key_as_gs_b = NULL;

    UA_STR(ua_as);
    UA_STR(ua_sgw);
    if (role == ROLE_AS) {
        key_get_handle(LD_AS, get_ua_str(snf_en->AS_UA, ua_as), get_ua_str(10000, ua_sgw), ROOT_KEY,
                       &snf_en->key_as_sgw_r_h);
    } else if (role == ROLE_SGW) {
        snf_en->key_as_gs_b = init_buffer_unptr();
        key_get_handle(LD_SGW, get_ua_str(10010, ua_as), get_ua_str(10000, ua_sgw), ROOT_KEY,
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
    return LDCAUC_OK;
}


int8_t snf_LME_AUTH(void *args) {
    snf_args_t *snf_args = (snf_args_t *) args;
    snf_obj.as_snf_en = init_snf_en(snf_args);
    l_err err;

    if ((err = change_state(&snf_obj.as_snf_en->auth_fsm, LD_AUTHC_EV_DEFAULT,
                            &(fsm_event_data_t) {
                                    &ld_authc_fsm_events[LD_AUTHC_A1], snf_obj.as_snf_en
                            }))) {
        log_error("cant change state correctly, %d", err);
        return LDCAUC_INTERNAL_ERROR;
    }
    return LDCAUC_OK;
}

int8_t exit_LME_AUTH(void) {
    if (snf_obj.finish_auth_func) {
        snf_obj.finish_auth_func();
        return LDCAUC_OK;
    }
    return LDCAUC_NULL;
}

int8_t register_snf_en(snf_args_t *snf_args) {
    if (snf_args->AS_SAC >= 4096 || snf_args->SGW_SAC >= 4096) return LDCAUC_WRONG_PARA;
    snf_entity_t *en = init_snf_en(snf_args);
    if (en == NULL) {
        return LDCAUC_NULL;
    }
    set_enode(en);

    return LDCAUC_OK;
}

int8_t unregister_snf_en(uint16_t SAC) {
    snf_obj.is_merged == FALSE
    ? trans_gsnf(snf_obj.sgw_conn, &(gsnf_st_chg_t) {
            .G_TYP = GSNF_STATE_CHANGE,
            .VER = DEFAULT_GSNF_VERSION,
            .AS_SAC = SAC,
            .State = GSNF_EXIT,
            .GS_SAC = snf_obj.GS_SAC
    }, &gsnf_st_chg_desc, NULL, NULL)
    : trans_gsnf(snf_obj.sgw_conn, &(gsg_as_exit_t) {GS_AS_EXIT, SAC},
                 &gsg_as_exit_desc, NULL, NULL);
    return delete_enode_by_sac(SAC, clear_snf_en);
}


static void free_snf_en(snf_entity_t *en) {
    clear_snf_en(en);
    free(en);
}


static buffer_t *gen_failed_pkt(uint8_t failed_type, uint16_t as_sac, buffer_t *failed_sdu) {
    return gen_pdu(&(failed_message_t) {
            .SN_TYP = FAILED_MESSAGE,
            .VER = snf_obj.PROTOCOL_VER,
            .PID = PID_RESERVED,
            .AS_SAC = as_sac,
            .FAILED_TYPE = failed_type,
            .msg = failed_sdu,
    }, &failed_message_desc, "FAILED MESSAGE");
}

int8_t upload_snf(bool is_valid, uint16_t AS_SAC, uint8_t *buf, size_t buf_len) {
    /* sub-net control will not have unacknowledged data */

    buffer_t *in_buf = init_buffer_unptr();
    CLONE_TO_CHUNK(*in_buf, buf, buf_len);
    buffer_t *to_trans_buf = NULL;
    if (snf_obj.role == LD_GS) {
        snf_entity_t *as_man = get_enode(AS_SAC);
        if (snf_obj.is_merged == TRUE) {
            // send failed message to SGW
            if (!is_valid) {
                to_trans_buf = gen_failed_pkt(0xFF, as_man->AS_SAC, in_buf);
                trans_gsnf(snf_obj.sgw_conn, &(gsg_pkt_t) {
                        GS_SNF_DOWNLOAD, as_man->AS_SAC, to_trans_buf
                }, &gsg_pkt_desc, NULL, NULL);
                free_buffer(to_trans_buf);
            } else {
                uint8_t type;
                to_trans_buf = in_buf;
                switch (*to_trans_buf->ptr) {
                    case AUC_RQST: {
                        type = GS_INITIAL_MSG;
                        break;
                    }
                    case SN_SESSION_EST_RESP: {
                        type = GS_UP_DOWNLOAD_TRANSPORT;
                        break;
                    }
                    default: {
                        type = GS_SNF_DOWNLOAD;
                    }
                }
                trans_gsnf(snf_obj.sgw_conn, &(gsg_pkt_t) {
                        type, as_man->AS_SAC, to_trans_buf
                }, &gsg_pkt_desc, NULL, NULL);
            }
        } else {
            to_trans_buf = in_buf;
            if (!is_valid) {
                to_trans_buf = gen_failed_pkt(0xFF, as_man->AS_SAC, in_buf);
                trans_gsnf(snf_obj.sgw_conn, &(gsnf_pkt_cn_t) {
                        GSNF_SNF_DOWNLOAD, DEFAULT_GSNF_VERSION, AS_SAC, 0xFF, to_trans_buf
                }, &gsnf_pkt_cn_desc, NULL, NULL);
                free_buffer(to_trans_buf);
            } else {
                if (as_man->gsnf_count++ == 0) {
                    trans_gsnf(snf_obj.sgw_conn, &(gsnf_pkt_cn_ini_t) {
                            GSNF_INITIAL_AS, DEFAULT_GSNF_VERSION, AS_SAC, ELE_TYP_F,
                            as_man->AS_UA,
                            to_trans_buf
                    }, &gsnf_pkt_cn_ini_desc, NULL, NULL);
                } else {
                    trans_gsnf(snf_obj.sgw_conn, &(gsnf_pkt_cn_t) {
                            GSNF_SNF_DOWNLOAD, DEFAULT_GSNF_VERSION, AS_SAC, ELE_TYP_F, to_trans_buf
                    }, &gsnf_pkt_cn_desc, NULL, NULL);
                }
            }
        }
    } else if (config.role == LD_AS) {
        const snf_entity_t *as_man = snf_obj.as_snf_en;
        to_trans_buf = in_buf;
        if (as_man == NULL) return LDCAUC_INTERNAL_ERROR;

        handle_recv_msg(to_trans_buf, as_man);
    }

    free_buffer(in_buf);

    return LDCAUC_OK;
}


