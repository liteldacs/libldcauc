//
// Created by 邹嘉旭 on 2025/4/3.
//

#include "snf.h"
#include "crypto/secure_core.h"
#include "crypto/authc.h"
#include "crypto/key.h"
#include "gs_conn.h"
#include "inside.h"

#define GSG_PKT_HEAD_LEN 2
#define GSG_SAC_HEAD_LEN 4
#define GSNF_PKT_CN_HEAD_LEN 4
#define GSNF_PKT_CN_INI_HEAD_LEN 9

#define GSNF_AS_AUZ_INFO_PRE_LEN 4


static gsg_pkt_t *init_gsg_pkg(size_t pdu_len) {
    gsg_pkt_t *gsnf_pkg = calloc(1, sizeof(gsg_pkt_t));
    gsnf_pkg->sdu = init_buffer_ptr(pdu_len - GSG_PKT_HEAD_LEN);
    return gsnf_pkg;
}

static gsg_ini_pkt_t *init_gsg_sac_pkg(size_t pdu_len) {
    gsg_ini_pkt_t *gsnf_sac = calloc(1, sizeof(gsg_ini_pkt_t));
    gsnf_sac->sdu = init_buffer_ptr(pdu_len - GSG_SAC_HEAD_LEN);
    return gsnf_sac;
}

static void free_gsg_pkg(gsg_pkt_t *gsnf_pkg) {
    if (gsnf_pkg->sdu) {
        free_buffer(gsnf_pkg->sdu);
    }
    free(gsnf_pkg);
}

static void free_gsg_sac_pkg(gsg_ini_pkt_t *gsnf_sac) {
    if (gsnf_sac->sdu) {
        free_buffer(gsnf_sac->sdu);
    }
    free(gsnf_sac);
}


static l_err parse_gsg_sac_reqp_pkt(buffer_t *pdu, gsg_sac_resp_t *gsg_sac_resp) {
    pb_stream gsg_sac_pbs;
    zero(&gsg_sac_pbs);

    init_pbs(&gsg_sac_pbs, pdu->ptr, pdu->len, "GSNF IN");

    if (!in_struct(gsg_sac_resp, &gsg_sac_resp_desc, &gsg_sac_pbs, NULL)) {
        log_error("Cannot parse gsg pdu");
        return LD_ERR_INTERNAL;
    }
    return LD_OK;
}


static l_err parse_gsg_pkt(buffer_t *pdu, gsg_pkt_t **gsnf_pkg_ptr, snf_entity_t **as_man) {
    pb_stream gsnf_pbs;
    zero(&gsnf_pbs);
    *gsnf_pkg_ptr = init_gsg_pkg(pdu->len);
    gsg_pkt_t *gsnf_pkg = *gsnf_pkg_ptr;

    init_pbs(&gsnf_pbs, pdu->ptr, pdu->len, "GSNF IN");

    if (!in_struct(gsnf_pkg, &gsg_pkt_desc, &gsnf_pbs, NULL)) {
        log_error("Cannot parse gsnf pdu");
        return LD_ERR_INTERNAL;
    }

    if (has_enode_by_sac(gsnf_pkg->AS_SAC) == FALSE) {
        return LD_ERR_INVALID;
    }

    *as_man = (snf_entity_t *) get_enode(gsnf_pkg->AS_SAC);

    // log_buf(LOG_INFO, "RECV GSG SDU", gsnf_pkg->sdu->ptr, gsnf_pkg->sdu->len);
    return LD_OK;
}

static l_err parse_gsg_data_pkt(buffer_t *pdu, gsg_data_t *data_pkt) {
    pb_stream gsnf_pbs;
    zero(&gsnf_pbs);
    data_pkt->sdu = init_buffer_ptr(pdu->len - GSG_DATA_PKT_HEAD_LEN);

    init_pbs(&gsnf_pbs, pdu->ptr, pdu->len, "GSNF IN");

    if (!in_struct(data_pkt, &gsg_pkt_desc, &gsnf_pbs, NULL)) {
        log_error("Cannot parse gsnf pdu");
        return LD_ERR_INTERNAL;
    }

    return LD_OK;
}

#define PARSE_GSNF(pdu, name, desc, head_len, pre_len) { \
    pb_stream gsnf_pbs; \
    zero(&gsnf_pbs); \
    name->sdu = init_buffer_ptr((pdu)->len - (head_len) - (pre_len));\
    init_pbs(&gsnf_pbs, (pdu)->ptr + (pre_len), (pdu)->len - (pre_len), "GSNF IN");\
    if (!in_struct(name, &desc, &gsnf_pbs, NULL)) { \
        log_error("Cannot parse gsnf pdu"); \
        free_buffer(name->sdu);\
        free(name);\
        break;\
    }\
}

l_err recv_gsnf(basic_conn_t *bc) {
    if (!bc->read_pkt) {
        log_warn("Read pkt is null");
        return LD_ERR_NULL;
    }
    gs_propt_t *gs_propt = (gs_propt_t *) bc;
    log_buf(LOG_INFO, "RECV GSNF", gs_propt->bc.read_pkt->ptr, gs_propt->bc.read_pkt->len);
    snf_entity_t *as_man;
    uint8_t gsnf_type = *gs_propt->bc.read_pkt->ptr;

    switch (gsnf_type) {
        case GSNF_INITIAL_AS: {
            gsnf_pkt_cn_ini_t *init_pkt = calloc(1, sizeof(gsnf_pkt_cn_ini_t));
            PARSE_GSNF(gs_propt->bc.read_pkt, init_pkt, gsnf_pkt_cn_ini_desc, GSNF_PKT_CN_INI_HEAD_LEN, 0);
            if (has_enode_by_sac(init_pkt->AS_SAC) == FALSE && has_enode_by_ua(init_pkt->UA) == FALSE) {
                if (register_snf_en(ROLE_SGW, init_pkt->AS_SAC, init_pkt->UA, init_pkt->GS_SAC) != LDCAUC_OK) {
                    log_warn("Can not register snf");
                    return LD_ERR_INTERNAL;
                }
            } else {
                log_warn("AS MAN or UA is already exist");
                return LD_ERR_INTERNAL;
            }

            if ((as_man = (snf_entity_t *) get_enode(init_pkt->AS_SAC)) == NULL) {
                log_warn("AS MAN is NULL");
                return LD_ERR_NULL;
            }

            as_man->gs_conn = gs_propt;

            handle_recv_msg(init_pkt->sdu, as_man);

            free_buffer(init_pkt->sdu);
            free(init_pkt);
            break;
        }
        case GSNF_SNF_UPLOAD:
        case GSNF_SNF_DOWNLOAD:
        case GSNF_AS_AUZ_INFO:
        case GSNF_KEY_TRANS: {
            gsnf_pkt_cn_t *gsnf_pkt = calloc(1, sizeof(gsnf_pkt_cn_t));
            PARSE_GSNF(gs_propt->bc.read_pkt, gsnf_pkt, gsnf_pkt_cn_desc, GSNF_PKT_CN_HEAD_LEN,
                       gsnf_type == GSNF_AS_AUZ_INFO ? GSNF_AS_AUZ_INFO_PRE_LEN : 0);
            if ((as_man = (snf_entity_t *) get_enode(gsnf_pkt->AS_SAC)) == NULL) {
                log_warn("AS MAN is NULL");
                return LD_ERR_NULL;
            }
            switch (gsnf_pkt->G_TYP) {
                case GSNF_SNF_UPLOAD: {
                    /* 构造具有指向性的传递结构，根据源和目的SAC指示下层向对应实体传输 */
                    snf_obj.trans_snp_func(as_man->AS_SAC, snf_obj.GS_SAC, gsnf_pkt->sdu->ptr, gsnf_pkt->sdu->len,
                                           TRUE);
                    break;
                }
                case GSNF_SNF_DOWNLOAD: {
                    handle_recv_msg(gsnf_pkt->sdu, as_man);
                    break;
                }
                case GSNF_KEY_TRANS: {
                    pb_stream pbs;
                    gs_key_trans_t key_trans = {
                        .key = init_buffer_ptr(ROOT_KEY_LEN),
                        .nonce = init_buffer_ptr(NONCE_LEN)
                    };

                    init_pbs(&pbs, gsnf_pkt->sdu->ptr, gsnf_pkt->sdu->len, "GS KEY GET");
                    if (in_struct(&key_trans, &gs_key_trans_desc, &pbs, NULL) == FALSE) {
                        return LD_ERR_INTERNAL;
                    }

                    UA_STR(ua_as);
                    UA_STR(ua_gs);
                    get_ua_str(as_man->AS_UA, ua_as);
                    get_ua_str(snf_obj.GS_SAC, ua_gs);

                    key_install(key_trans.key, ua_as, ua_gs, key_trans.nonce->ptr, key_trans.nonce->len,
                                &as_man->key_as_gs_h);

                    /* 未来使用切换状态机， 抛弃这种方法*/
                    if (snf_obj.GS_SAC != as_man->CURR_GS_SAC) {
                        snf_obj.gst_ho_complete_key_func(as_man->AS_SAC, as_man->AS_UA, as_man->CURR_GS_SAC);
                    }

                    free_buffer(key_trans.key);
                    free_buffer(key_trans.nonce);
                    as_man->gs_finish_auth = TRUE;
                    break;
                }
                default: {
                    log_error("Wrong GSNF Type");
                    return LD_ERR_WRONG_PARA;
                }
            }
            free_buffer(gsnf_pkt->sdu);
            free(gsnf_pkt);
            break;
        }
        case GSNF_STATE_CHANGE: {
            gsnf_st_chg_t *gsnf_pkt = calloc(1, sizeof(gsnf_st_chg_t));
            pb_stream gsnf_pbs;
            zero(&gsnf_pbs);
            init_pbs(&gsnf_pbs, gs_propt->bc.read_pkt->ptr, gs_propt->bc.read_pkt->len, "GSNF IN");
            if (!in_struct(gsnf_pkt, &gsnf_st_chg_desc, &gsnf_pbs, NULL)) {
                log_error("Cannot parse gsnf pdu");
                free(gsnf_pkt);
                break;
            }
            switch (gsnf_pkt->State) {
                case GSNF_ACCESS: {
                    log_info("Successfully Access In");
                    break;
                }
                case GSNF_EXIT: {
                    delete_enode_by_sac(gsnf_pkt->AS_SAC, clear_snf_en);
                    break;
                }
                default: {
                    break;
                }
            }
            // if (gsnf_pkt->State == GSNF_EXIT) {
            //     delete_enode_by_sac(gsnf_pkt->AS_SAC, clear_snf_en);
            // }

            free(gsnf_pkt);
            break;
        }
        case GSNF_KEY_UPD_REMIND: {
            gsnf_key_upd_remind_t *gsnf_pkt = calloc(1, sizeof(gsnf_key_upd_remind_t));
            pb_stream gsnf_pbs;
            zero(&gsnf_pbs);
            init_pbs(&gsnf_pbs, gs_propt->bc.read_pkt->ptr, gs_propt->bc.read_pkt->len, "GSNF IN");
            if (!in_struct(gsnf_pkt, &gsnf_key_upd_remind_desc, &gsnf_pbs, NULL)) {
                log_error("Cannot parse gsnf pdu");
                free(gsnf_pkt);
                break;
            }

            if ((as_man = (snf_entity_t *) get_enode(gsnf_pkt->AS_SAC)) == NULL) {
                log_warn("AS MAN is NULL");
                return LD_ERR_NULL;
            }

            send_key_update_rqst(as_man, gsnf_pkt->GST_SAC);

            free(gsnf_pkt);
            break;
        }
        default: {
            log_error("Wrong GSNF type");
            return LD_ERR_WRONG_PARA;
        }
    }
    return LD_OK;
}

l_err recv_gsg(basic_conn_t *bc) {
    if (!bc->read_pkt) return LD_ERR_NULL;
    gs_propt_t *mlt_ld = (gs_propt_t *) bc;
    log_buf(LOG_INFO, "RECV GSG", mlt_ld->bc.read_pkt->ptr, mlt_ld->bc.read_pkt->len);
    switch ((*mlt_ld->bc.read_pkt->ptr >> (BITS_PER_BYTE - GTYP_LEN)) & (0xFF >> (BITS_PER_BYTE - GTYP_LEN))) {
        case GS_INITIAL_MSG:
            break;
        //        case GS_SAC_RESP: {
        //            gsg_sac_pkt_t *gsnf_sac_pkg;
        //            if (parse_gsg_sac_pkt(&mlt_ld->bc->read_pkt, &gsnf_sac_pkg) != LD_OK) {
        //                return LD_ERR_INTERNAL;
        //            }
        //            switch (gsnf_sac_pkg->TYPE) {
        //                case GS_SAC_RESP: {
        //                    pb_stream pbs;
        //                    gs_sac_resp_sdu_t resp;
        //
        //                    init_pbs(&pbs, gsnf_sac_pkg->sdu->ptr, gsnf_sac_pkg->sdu->len, "GS SAC RESP");
        //                    if (in_struct(&resp, &gs_sac_resp_desc, &pbs, NULL) == FALSE) {
        //                        return LD_ERR_INTERNAL;
        //                    }
        //
        //                    if (has_enode_by_sac(resp.SAC) == FALSE) {
        //                        // set_enode(init_as_man(resp.SAC, gsnf_sac_pkg->UA, lme_layer_objs.GS_SAC, LD_AUTHC_G0));
        //                        register_snf_en(&(snf_args_t) {
        //                                .role = ROLE_SGW,
        //                                .AS_UA = gsnf_sac_pkg->UA,
        //                                .AS_SAC = resp.SAC,
        //                                .SGW_SAC = snf_obj.GS_SAC
        //                        });
        //                    }
        //
        //                    /* TODO: 执行dls open的callback */
        //                    // dls_en_data_t *dls_en_data = &(dls_en_data_t) {
        //                    //     .
        //                    //     GS_SAC = lme_layer_objs.GS_SAC,
        //                    //     .
        //                    //     AS_UA = gsnf_sac_pkg->UA,
        //                    //     .
        //                    //     AS_SAC = resp.SAC, //和GSC共同协商分配给AS的SAC 10.6.4.5
        //                    // };
        //                    //
        //                    // preempt_prim(&DLS_OPEN_REQ_PRIM, DL_TYP_GS_INIT, dls_en_data, NULL, 0, 0);
        //                    break;
        //                }
        //                default: {
        //                    break;
        //                }
        //            }
        //
        //            free_gsg_sac_pkg(gsnf_sac_pkg);
        //            break;
        //        }
        case GS_SNF_UPLOAD:
        case GS_SNF_DOWNLOAD:
        case GS_UP_UPLOAD_TRANSPORT:
        case GS_KEY_TRANS: {
            gsg_pkt_t *gsnf_pkg;
            snf_entity_t *as_man;
            if (parse_gsg_pkt(mlt_ld->bc.read_pkt, &gsnf_pkg, &as_man) != LD_OK) {
                return LD_ERR_INTERNAL;
            }
            switch (gsnf_pkg->TYPE) {
                case GS_UP_UPLOAD_TRANSPORT:
                case GS_SNF_UPLOAD: {
                    snf_obj.trans_snp_func(as_man->AS_SAC, snf_obj.GS_SAC, gsnf_pkg->sdu->ptr, gsnf_pkg->sdu->len,
                                           TRUE);
                    break;
                }
                case GS_SNF_DOWNLOAD: {
                    handle_recv_msg(gsnf_pkg->sdu, as_man);
                    break;
                }
                case GS_KEY_TRANS: {
                    pb_stream pbs;
                    gs_key_trans_t key_trans = {
                        .key = init_buffer_ptr(ROOT_KEY_LEN),
                        .nonce = init_buffer_ptr(NONCE_LEN)
                    };

                    init_pbs(&pbs, gsnf_pkg->sdu->ptr, gsnf_pkg->sdu->len, "GS KEY GET");
                    if (in_struct(&key_trans, &gs_key_trans_desc, &pbs, NULL) == FALSE) {
                        return LD_ERR_INTERNAL;
                    }

                    UA_STR(ua_as);
                    UA_STR(ua_gs);
                    get_ua_str(as_man->AS_UA, ua_as);
                    get_ua_str(as_man->CURR_GS_SAC, ua_gs);

                    key_install(key_trans.key, ua_as, ua_gs, key_trans.nonce->ptr, key_trans.nonce->len,
                                &as_man->key_as_gs_h);

                    /* 未来使用切换状态机， 抛弃这种方法*/
                    if (snf_obj.GS_SAC != as_man->CURR_GS_SAC) {
                        snf_obj.gst_ho_complete_key_func(as_man->AS_SAC, as_man->AS_UA, as_man->CURR_GS_SAC);
                    }

                    free_buffer(key_trans.key);
                    free_buffer(key_trans.nonce);
                    as_man->gs_finish_auth = TRUE;
                    break;
                }
                default: {
                    return LD_ERR_WRONG_PARA;
                }
            }
            free_gsg_pkg(gsnf_pkg);
            break;
        }
        case GS_SAC_RESP: {
            gsg_sac_resp_t resp;
            if (parse_gsg_sac_reqp_pkt(mlt_ld->bc.read_pkt, &resp) != LD_OK) {
                return LD_ERR_INTERNAL;
            };
            if (snf_obj.setup_entity_func) {
                snf_obj.setup_entity_func(resp.AS_SAC, resp.AS_UA);
            }
            // inside_combine_sac_response(resp.AS_SAC, resp.AS_UA);
            break;
        }
        case GS_DATA_UP: {
            gsg_data_t data_pkt;
            if (parse_gsg_data_pkt(mlt_ld->bc.read_pkt, &data_pkt) != LD_OK) {
                return LD_ERR_INTERNAL;
            }
            snf_obj.trans_snp_func(data_pkt.AS_SAC, snf_obj.GS_SAC, data_pkt.sdu->ptr, data_pkt.sdu->len, FALSE);
            break;
        }
        default: {
            return LD_ERR_WRONG_PARA;
        }
    }


    return LD_OK;
}
