//
// Created by 邹嘉旭 on 2025/3/30.
//
#include "snf.h"

#include "gsc_conn.h"
#include "crypto/authc.h"
#include "crypto/key.h"


snf_obj_t snf_obj = {
    .PROTOCOL_VER = PROTECT_VERSION,
};

void init_as_snf_layer(finish_auth finish_auth, trans_snp trans_snp, register_snf_fail register_fail) {
    snf_obj.snf_emap = init_enode_map();
    snf_obj.role = LD_AS;

    snf_obj.finish_auth_func = finish_auth;
    snf_obj.trans_snp_func = trans_snp;
    snf_obj.register_fail_func = register_fail;
}

void init_gs_snf_layer(uint16_t GS_SAC, char *gsnf_addr, uint16_t gsnf_remote_port, uint16_t gsnf_local_port,
                       trans_snp trans_snp, register_snf_fail register_fail,
                       gst_ho_complete_key gst_ho_complete_key) {
    snf_obj.snf_emap = init_enode_map();
    snf_obj.role = LD_GS;
    snf_obj.GS_SAC = GS_SAC;
    snf_obj.is_merged = TRUE;

    snf_obj.trans_snp_func = trans_snp;
    snf_obj.register_fail_func = register_fail;
    snf_obj.gst_ho_complete_key_func = gst_ho_complete_key;

    if (init_client_gs_conn_service(gsnf_addr, gsnf_remote_port, gsnf_local_port, recv_gsg) != LD_OK) {
        log_warn("Cannot init GS connection service");
    }
}


void init_gs_snf_layer_unmerged(uint16_t GS_SAC, char *gsnf_addr, uint16_t gsnf_remote_port, uint16_t gsnf_local_port,
                                trans_snp trans_snp, register_snf_fail register_fail, gst_ho_complete_key finish_ho) {
    snf_obj.snf_emap = init_enode_map();
    snf_obj.role = LD_GS;
    snf_obj.GS_SAC = GS_SAC;
    snf_obj.is_merged = FALSE;


    snf_obj.trans_snp_func = trans_snp;
    snf_obj.register_fail_func = register_fail;
    snf_obj.gst_ho_complete_key_func = finish_ho;
    if (init_client_gs_conn_service(gsnf_addr, gsnf_remote_port, gsnf_local_port, recv_gsnf) != LD_OK) {
        log_warn("Cannot init GS connection service");
    }
}

void init_sgw_snf_layer(uint16_t listen_port) {
    snf_obj.snf_emap = init_enode_map();
    snf_obj.role = LD_SGW;
    snf_obj.is_merged = TRUE;

    snf_obj.register_fail_func = NULL;

    if (init_server_gsc_conn_service(listen_port) != LD_OK) {
        log_warn("Cannot init GSC connection service");
    }
}


void init_sgw_snf_layer_unmerged(uint16_t listen_port) {
    snf_obj.snf_emap = init_enode_map();
    snf_obj.role = LD_SGW;
    snf_obj.is_merged = FALSE;

    snf_obj.register_fail_func = NULL;

    if (init_server_gs_conn_service(listen_port) != LD_OK) {
        log_warn("Cannot init GS connection service");
    }
}


int8_t destory_snf_layer() {
    hashmap_free(snf_obj.snf_emap);
    return LDCAUC_OK;
}

static snf_entity_t *init_snf_en(uint8_t role, uint16_t AS_SAC, uint32_t AS_UA, uint16_t GS_SAC) {
    snf_entity_t *snf_en = calloc(1, sizeof(snf_entity_t));

    snf_en->AS_SAC = AS_SAC;
    snf_en->AS_UA = AS_UA;
    snf_en->CURR_GS_SAC = GS_SAC;

    snf_en->AUTHC_MACLEN = AUTHC_MACLEN_256; /* default mac len is 256  */
    snf_en->AUTHC_AUTH_ID = AUTHC_AUTH_SM3HMAC;
    snf_en->AUTHC_ENC_ID = AUTHC_ENC_SM4_CBC;
    snf_en->AUTHC_KLEN = AUTHC_KLEN_128;

    snf_en->shared_random = NULL;
    snf_en->key_as_gs_b = NULL;

    UA_STR(ua_as);
    UA_STR(ua_sgw);

    if (role == ROLE_AS) {
        if (embed_rootkey(LD_AS, get_ua_str(snf_en->AS_UA, ua_as), get_ua_str(DFT_SGW_UA, ua_sgw)) != LD_KM_OK ||
            key_get_handle(LD_AS, get_ua_str(snf_en->AS_UA, ua_as), get_ua_str(DFT_SGW_UA, ua_sgw), ROOT_KEY,
                           &snf_en->key_as_sgw_r_h) != LD_KM_OK) {
            log_error("Embed or Get rootkey Error");
            free(snf_en);
            return NULL;
        }
    } else if (role == ROLE_SGW) {
        snf_en->key_as_gs_b = init_buffer_unptr();
        if (embed_rootkey(LD_SGW, get_ua_str(snf_en->AS_UA, ua_as), get_ua_str(DFT_SGW_UA, ua_sgw)) != LD_KM_OK ||
            key_get_handle(LD_SGW, get_ua_str(snf_en->AS_UA, ua_as), get_ua_str(DFT_SGW_UA, ua_sgw), ROOT_KEY,
                           &snf_en->key_as_sgw_r_h) != LD_KM_OK) {
            log_error("Embed or Get rootkey Error");
            free(snf_en);
            return NULL;
        }
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

    UA_STR(ua_as);
    UA_STR(ua_gs);
    UA_STR(ua_sgw);
    get_ua_str(snf_en->AS_UA, ua_as);
    get_ua_str(snf_obj.GS_SAC, ua_gs);
    get_ua_str(DFT_SGW_UA, ua_sgw);
    snf_obj.role == LD_GS
        ? revoke_key(snf_obj.role, ua_as, ua_gs, MASTER_KEY_AS_GS)
        : revoke_key(snf_obj.role, ua_as, ua_sgw, MASTER_KEY_AS_SGW);

#ifdef UNUSE_CRYCARD
    if (snf_en->key_as_sgw_r_h != NULL) { free_buffer(snf_en->key_as_sgw_r_h); }
    if (snf_en->key_as_sgw_s_h != NULL) { free_buffer(snf_en->key_as_sgw_s_h); }
    if (snf_en->key_as_gs_h != NULL) { free_buffer(snf_en->key_as_gs_h); }
    if (snf_en->key_session_en_h != NULL) { free_buffer(snf_en->key_session_en_h); }
    if (snf_en->key_session_mac_h != NULL) { free_buffer(snf_en->key_session_mac_h); }
#endif
    return LDCAUC_OK;
}

int8_t snf_LME_AUTH(uint8_t role, uint16_t AS_SAC, uint32_t AS_UA, uint16_t GS_SAC) {
    snf_obj.as_snf_en = init_snf_en(role, AS_SAC, AS_UA, GS_SAC);
    if (!snf_obj.as_snf_en) {
        if (snf_obj.register_fail_func) {
            snf_obj.register_fail_func(AS_SAC);
        }
        return LDCAUC_INTERNAL_ERROR;
    }
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

int8_t exit_LME_AUTH(void) {
    if (snf_obj.finish_auth_func) {
        snf_obj.finish_auth_func();
        return LDCAUC_OK;
    }
    return LDCAUC_NULL;
}

int8_t register_snf_en(uint8_t role, uint16_t AS_SAC, uint32_t AS_UA, uint16_t GS_SAC) {
    if (role != ROLE_AS && role != ROLE_GS && role != ROLE_SGW) return LDCAUC_WRONG_PARA;

    if (AS_SAC >= 4096 || GS_SAC >= 4096) return LDCAUC_WRONG_PARA;
    snf_entity_t *en = init_snf_en(role, AS_SAC, AS_UA, GS_SAC);
    if (en == NULL) {
        if (snf_obj.register_fail_func) {
            snf_obj.register_fail_func(AS_SAC);
        }
        return LDCAUC_INTERNAL_ERROR;
    }
    set_enode(en);

    return LDCAUC_OK;
}

int8_t unregister_snf_en(uint16_t AS_SAC) {
    if (snf_obj.role == ROLE_AS) {
        return clear_snf_en(snf_obj.as_snf_en);
    } else {
        return delete_enode_by_sac(AS_SAC, clear_snf_en);
    }
}

int8_t exit_snf_en(uint16_t AS_SAC) {
    if (snf_obj.role != ROLE_GS) return LDCAUC_WRONG_ROLE;
    snf_obj.is_merged == FALSE
        ? gs_conn_service.sgw_conn->bc.opt->send_handler(&gs_conn_service.sgw_conn->bc, &(gsnf_st_chg_t){
                                                             .G_TYP = GSNF_STATE_CHANGE,
                                                             .VER = DEFAULT_GSNF_VERSION,
                                                             .AS_SAC = AS_SAC,
                                                             .State = GSNF_EXIT,
                                                             .GS_SAC = snf_obj.GS_SAC
                                                         }, &gsnf_st_chg_desc, NULL, NULL)
        : gs_conn_service.sgw_conn->bc.opt->send_handler(&gs_conn_service.sgw_conn->bc,
                                                         &(gsg_as_exit_t){GS_AS_EXIT, AS_SAC},
                                                         &gsg_as_exit_desc, NULL, NULL);
    return delete_enode_by_sac(AS_SAC, clear_snf_en);
}


static buffer_t *gen_failed_pkt(uint8_t failed_type, uint16_t as_sac, buffer_t *failed_sdu) {
    return gen_pdu(&(failed_message_t){
                       .SN_TYP = FAILED_MESSAGE,
                       .VER = snf_obj.PROTOCOL_VER,
                       .PID = PID_RESERVED,
                       .AS_SAC = as_sac,
                       .FAILED_TYPE = failed_type,
                       .msg = failed_sdu,
                   }, &failed_message_desc, "FAILED MESSAGE");
}

int8_t upload_snf(bool is_valid, uint16_t AS_SAC, uint16_t GS_SAC, uint8_t *snp_buf, size_t buf_len) {
    /* sub-net control will not have unacknowledged data */

    buffer_t *in_buf = init_buffer_unptr();
    CLONE_TO_CHUNK(*in_buf, snp_buf, buf_len);
    buffer_t *to_trans_buf = NULL;
    if (snf_obj.role == LD_GS) {
        snf_entity_t *as_man = get_enode(AS_SAC);
        if (snf_obj.is_merged == TRUE) {
            // send failed message to SGW
            if (!is_valid) {
                to_trans_buf = gen_failed_pkt(0xFF, as_man->AS_SAC, in_buf);
                gs_conn_service.sgw_conn->bc.opt->send_handler(&gs_conn_service.sgw_conn->bc, &(gsg_pkt_t){
                                                                   GS_SNF_DOWNLOAD, as_man->AS_SAC, to_trans_buf
                                                               }, &gsg_pkt_desc, NULL, NULL);
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
                if (as_man->gsnf_count++ == 0) {
                    gs_conn_service.sgw_conn->bc.opt->send_handler(&gs_conn_service.sgw_conn->bc, &(gsg_ini_pkt_t){
                                                                       type, as_man->AS_SAC, as_man->AS_UA, GS_SAC,
                                                                       to_trans_buf
                                                                   }, &gsg_ini_pkt_desc, NULL, NULL);
                } else {
                    gs_conn_service.sgw_conn->bc.opt->send_handler(&gs_conn_service.sgw_conn->bc, &(gsg_pkt_t){
                                                                       type, as_man->AS_SAC, to_trans_buf
                                                                   }, &gsg_pkt_desc, NULL, NULL);
                }
            }
        } else {
            to_trans_buf = in_buf;
            if (!is_valid) {
                to_trans_buf = gen_failed_pkt(0xFF, as_man->AS_SAC, in_buf);
                gs_conn_service.sgw_conn->bc.opt->send_handler(&gs_conn_service.sgw_conn->bc, &(gsnf_pkt_cn_t){
                                                                   GSNF_SNF_DOWNLOAD, DEFAULT_GSNF_VERSION, AS_SAC,
                                                                   0xFF,
                                                                   to_trans_buf
                                                               }, &gsnf_pkt_cn_desc, NULL, NULL);
                // free_buffer(to_trans_buf);
            } else {
                if (as_man->gsnf_count++ == 0) {
                    gs_conn_service.sgw_conn->bc.opt->send_handler(&gs_conn_service.sgw_conn->bc, &(gsnf_pkt_cn_ini_t){
                                                                       GSNF_INITIAL_AS, DEFAULT_GSNF_VERSION, AS_SAC,
                                                                       as_man->AS_UA, GS_SAC, ELE_TYP_F, to_trans_buf
                                                                   }, &gsnf_pkt_cn_ini_desc, NULL, NULL);
                } else {
                    gs_conn_service.sgw_conn->bc.opt->send_handler(&gs_conn_service.sgw_conn->bc, &(gsnf_pkt_cn_t){
                                                                       GSNF_SNF_DOWNLOAD, DEFAULT_GSNF_VERSION, AS_SAC,
                                                                       ELE_TYP_F, to_trans_buf
                                                                   }, &gsnf_pkt_cn_desc, NULL, NULL);
                }
            }
        }
    } else if (snf_obj.role == LD_AS) {
        const snf_entity_t *as_man = snf_obj.as_snf_en;
        to_trans_buf = in_buf;
        if (as_man == NULL) return LDCAUC_NULL;

        handle_recv_msg(to_trans_buf, as_man);
    }

    free_buffer(in_buf);
    return LDCAUC_OK;
}

int8_t gss_handover_request_trigger(uint16_t AS_SAC, uint16_t GSS_SAC, uint16_t GST_SAC) {
    if (snf_obj.is_merged == TRUE)
        gs_conn_service.sgw_conn->bc.opt->send_handler(&gs_conn_service.sgw_conn->bc, &(gsg_ho_req_t){
                                                           GS_HO_REQUEST, AS_SAC, GSS_SAC, GST_SAC,
                                                       }, &gsg_ho_req_desc, NULL, NULL);
    return LDCAUC_OK;
}


int8_t gst_handover_request_handle(uint16_t AS_SAC, uint32_t AS_UA, uint16_t GSS_SAC, uint16_t GST_SAC) {
    register_snf_en(ROLE_GS, AS_SAC, AS_UA, GSS_SAC);
    if (snf_obj.is_merged) {
        gs_conn_service.sgw_conn->bc.opt->send_handler(&gs_conn_service.sgw_conn->bc, &(gsg_ho_req_t){
                                                           GS_HO_REQUEST, AS_SAC, GSS_SAC, GST_SAC,
                                                       }, &gsg_ho_req_desc, NULL, NULL);
    } else {
        /* GS SAC for current GS (before handover) */
        gs_conn_service.sgw_conn->bc.opt->send_handler(&gs_conn_service.sgw_conn->bc, &(gsnf_key_upd_remind_t){
                                                           GSNF_KEY_UPD_REMIND, DEFAULT_GSNF_VERSION, AS_SAC, ELE_TYP_C,
                                                           GSS_SAC, GST_SAC
                                                       }, &gsnf_key_upd_remind_desc, NULL, NULL);
    }
    return LDCAUC_OK;
}

int8_t gst_handover_complete(uint16_t AS_SAC) {
    if (snf_obj.is_merged) {
        gs_conn_service.sgw_conn->bc.opt->send_handler(&gs_conn_service.sgw_conn->bc, &(gsg_ho_cplt_t){
                                                           .TYPE = GS_HO_COMPLETE,
                                                           .AS_SAC = AS_SAC,
                                                           .GS_SAC = snf_obj.GS_SAC
                                                       }, &gsg_ho_cplt_desc, NULL, NULL);
    } else {
        gs_conn_service.sgw_conn->bc.opt->send_handler(&gs_conn_service.sgw_conn->bc, &(gsnf_st_chg_t){
                                                           .G_TYP = GSNF_STATE_CHANGE,
                                                           .VER = DEFAULT_GSNF_VERSION,
                                                           .AS_SAC = AS_SAC,
                                                           .State = GSNF_SWITCH,
                                                           .GS_SAC = snf_obj.GS_SAC
                                                       }, &gsnf_st_chg_desc, NULL, NULL);
    }
    return LDCAUC_OK;
}
