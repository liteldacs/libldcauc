//
// Created by 邹嘉旭 on 2025/4/3.
//

#include "snf.h"
#include "crypto/secure_core.h"
#include "crypto/authc.h"
#include "crypto/key.h"

#define GSG_PKT_HEAD_LEN 2
#define GSG_SAC_HEAD_LEN 4
#define GSNF_PKT_CN_HEAD_LEN 4
#define GSNF_PKT_CN_INI_HEAD_LEN 7

#define GSNF_AS_AUZ_INFO_PRE_LEN 4


static gsg_pkt_t *init_gsg_pkg(size_t pdu_len) {
    gsg_pkt_t *gsnf_pkg = calloc(1, sizeof(gsg_pkt_t));
    gsnf_pkg->sdu = init_buffer_ptr(pdu_len - GSG_PKT_HEAD_LEN);
    return gsnf_pkg;
}

static gsg_sac_pkt_t *init_gsg_sac_pkg(size_t pdu_len) {
    gsg_sac_pkt_t *gsnf_sac = calloc(1, sizeof(gsg_sac_pkt_t));
    gsnf_sac->sdu = init_buffer_ptr(pdu_len - GSG_SAC_HEAD_LEN);
    return gsnf_sac;
}

static void free_gsg_pkg(gsg_pkt_t *gsnf_pkg) {
    if (gsnf_pkg->sdu) {
        free_buffer(gsnf_pkg->sdu);
    }
    free(gsnf_pkg);
}

static void free_gsg_sac_pkg(gsg_sac_pkt_t *gsnf_sac) {
    if (gsnf_sac->sdu) {
        free_buffer(gsnf_sac->sdu);
    }
    free(gsnf_sac);
}


l_err trans_gsnf(gs_tcp_propt_t *conn, void *pkg, struct_desc_t *desc, l_err (*mid_func)(buffer_t *, void *),
                 void *args) {
    if (conn == NULL) return LD_ERR_INTERNAL;
    pb_stream gsnf_pbs;
    uint8_t gsnf_raw[MAX_SNP_SDU_LEN] = {0};


    init_pbs(&gsnf_pbs, gsnf_raw, GSNF_MSG_MAX_LEN, "GSNF BUF");
    if (!out_struct(pkg, desc, &gsnf_pbs, NULL)) {
        log_error("Cannot generate GSNF message!");
        return LD_ERR_INTERNAL;
    }

    close_output_pbs(&gsnf_pbs);

    buffer_t *gsnf_buf = init_buffer_unptr();
    if (mid_func) {
        mid_func(gsnf_buf, args);
    }
    // CLONE_TO_CHUNK(*gsnf_buf, gsnf_pbs.start, pbs_offset(&gsnf_pbs));
    cat_to_buffer(gsnf_buf, gsnf_pbs.start, pbs_offset(&gsnf_pbs));
    log_buf(LOG_FATAL, "GSNF OUT", gsnf_buf->ptr, gsnf_buf->len);

    lfqueue_put(conn->bc.write_pkts, gsnf_buf);

    net_epoll_out(epoll_fd, &conn->bc);

    return LD_OK;
}

static l_err parse_gsg_sac_pkt(buffer_t *pdu, gsg_sac_pkt_t **gsnf_pkg_ptr) {
    pb_stream gsnf_sac_pbs;
    zero(&gsnf_sac_pbs);
    *gsnf_pkg_ptr = init_gsg_sac_pkg(pdu->len);
    gsg_sac_pkt_t *gsnf_sac_pkg = *gsnf_pkg_ptr;


    init_pbs(&gsnf_sac_pbs, pdu->ptr, pdu->len, "GSNF IN");

    if (!in_struct(gsnf_sac_pkg, &gsg_sac_pkt_desc, &gsnf_sac_pbs, NULL)) {
        log_error("Cannot parse gsnf pdu");
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

    log_buf(LOG_DEBUG, "RECV GSNF SDU", gsnf_pkg->sdu->ptr, gsnf_pkg->sdu->len);
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
    gs_tcp_propt_t *mlt_ld = (gs_tcp_propt_t *) bc;
    log_buf(LOG_INFO, "RECV GSNF", mlt_ld->bc.read_pkt.ptr, mlt_ld->bc.read_pkt.len);
    snf_entity_t *as_man;
    uint8_t gsnf_type = *mlt_ld->bc.read_pkt.ptr;

    switch (gsnf_type) {
        case GSNF_INITIAL_AS: {
            gsnf_pkt_cn_ini_t *init_pkt = calloc(1, sizeof(gsnf_pkt_cn_ini_t));
            PARSE_GSNF(&mlt_ld->bc.read_pkt, init_pkt, gsnf_pkt_cn_ini_desc, GSNF_PKT_CN_INI_HEAD_LEN, 0);
            if (has_enode_by_sac(init_pkt->AS_SAC) == FALSE && has_enode_by_ua(init_pkt->UA) == FALSE) {
                if (register_snf_en(ROLE_SGW, init_pkt->AS_SAC, init_pkt->UA, init_pkt->GS_SAC) != LDCAUC_OK) {
                    log_warn("Can not register snf");
                    return LD_ERR_INTERNAL;
                }
            } else {
                return LD_ERR_INTERNAL;
            }

            if ((as_man = (snf_entity_t *) get_enode(init_pkt->AS_SAC)) == NULL) {
                log_warn("AS MAN is NULL");
                return LD_ERR_NULL;
            }
            as_man->gs_conn = mlt_ld;

            handle_recv_msg(init_pkt->sdu, as_man);

            free_buffer(init_pkt->sdu);
            free(init_pkt);
            break;
        }
        case GSNF_SNF_UPLOAD:
        case GSNF_SNF_DOWNLOAD:
        case GSNF_AS_AUZ_INFO:
        case GSNF_KEY_TRANS: {
            gsnf_pkt_cn_t *gsnf_pkt = calloc(1, sizeof(gsnf_pkt_cn_ini_t));
            PARSE_GSNF(&mlt_ld->bc.read_pkt, gsnf_pkt, gsnf_pkt_cn_desc, GSNF_PKT_CN_HEAD_LEN,
                       gsnf_type == GSNF_AS_AUZ_INFO ? GSNF_AS_AUZ_INFO_PRE_LEN : 0);
            if ((as_man = (snf_entity_t *) get_enode(gsnf_pkt->AS_SAC)) == NULL) {
                log_warn("AS MAN is NULL");
                return LD_ERR_NULL;
            }
            switch (gsnf_pkt->G_TYP) {
                case GSNF_SNF_UPLOAD: {
                    /* 构造具有指向性的传递结构，根据源和目的SAC指示下层向对应实体传输 */

                    snf_obj.trans_snp_func(as_man->AS_SAC, snf_obj.GS_SAC, gsnf_pkt->sdu->ptr, gsnf_pkt->sdu->len);
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
                        .nonce = init_buffer_ptr(SHAREDINFO_LEN)
                    };

                    init_pbs(&pbs, gsnf_pkt->sdu->ptr, gsnf_pkt->sdu->len, "GS KEY GET");
                    if (in_struct(&key_trans, &gs_key_trans_desc, &pbs, NULL) == FALSE) {
                        return LD_ERR_INTERNAL;
                    }

                    UA_STR(ua_as);
                    UA_STR(ua_gs);
                    get_ua_str(as_man->AS_UA, ua_as);
                    get_ua_str(as_man->GS_SAC, ua_gs);

                    gs_install_keys(key_trans.key, key_trans.nonce->ptr, key_trans.nonce->len, ua_as, ua_gs,
                                    &as_man->key_as_gs_h);

                    free_buffer(key_trans.key);
                    free_buffer(key_trans.nonce);
                    as_man->gs_finish_auth = TRUE;
                    break;
                }
                default: {
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
            init_pbs(&gsnf_pbs, mlt_ld->bc.read_pkt.ptr, mlt_ld->bc.read_pkt.len, "GSNF IN");
            if (!in_struct(gsnf_pkt, &gsnf_st_chg_desc, &gsnf_pbs, NULL)) {
                log_error("Cannot parse gsnf pdu");
                free(gsnf_pkt);
                break;
            }
            if (gsnf_pkt->State == GSNF_EXIT) {
                delete_enode_by_sac(gsnf_pkt->AS_SAC, clear_snf_en);
            }

            free(gsnf_pkt);
            break;
        }
        default: {
            return LD_ERR_WRONG_PARA;
        }
    }
    return LD_OK;
}

l_err recv_gsg(basic_conn_t *bc) {
    gs_tcp_propt_t *mlt_ld = (gs_tcp_propt_t *) bc;
    log_buf(LOG_INFO, "RECV GSG", mlt_ld->bc.read_pkt.ptr, mlt_ld->bc.read_pkt.len);
    switch ((*mlt_ld->bc.read_pkt.ptr >> (BITS_PER_BYTE - GTYP_LEN)) & (0xFF >> (BITS_PER_BYTE - GTYP_LEN))) {
        //        case GS_SAC_RQST:
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
            if (parse_gsg_pkt(&mlt_ld->bc.read_pkt, &gsnf_pkg, &as_man) != LD_OK) {
                return LD_ERR_INTERNAL;
            }
            switch (gsnf_pkg->TYPE) {
                case GS_UP_UPLOAD_TRANSPORT:
                case GS_SNF_UPLOAD: {
                    snf_obj.trans_snp_func(as_man->AS_SAC, snf_obj.GS_SAC, gsnf_pkg->sdu->ptr, gsnf_pkg->sdu->len);
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
                        .nonce = init_buffer_ptr(SHAREDINFO_LEN)
                    };

                    init_pbs(&pbs, gsnf_pkg->sdu->ptr, gsnf_pkg->sdu->len, "GS KEY GET");
                    if (in_struct(&key_trans, &gs_key_trans_desc, &pbs, NULL) == FALSE) {
                        return LD_ERR_INTERNAL;
                    }

                    UA_STR(ua_as);
                    UA_STR(ua_gs);
                    get_ua_str(as_man->AS_UA, ua_as);
                    get_ua_str(as_man->GS_SAC, ua_gs);

                    gs_install_keys(key_trans.key, key_trans.nonce->ptr, key_trans.nonce->len, ua_as, ua_gs,
                                    &as_man->key_as_gs_h);

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
        default: {
            return LD_ERR_WRONG_PARA;
        }
    }


    return LD_OK;
}
