//
// Created by 邹嘉旭 on 2025/4/3.
//

#include "snf.h"
#include "crypto/authc.h"

fsm_event_t ld_authc_fsm_events[] = {
    {"LD_AUTHC_A0", NULL, NULL},
    {"LD_AUTHC_A1", send_auc_rqst, NULL},
    {"LD_AUTHC_A2", send_auc_key_exec, NULL},
    {"LD_AUTHC_G0", NULL, NULL},
    {"LD_AUTHC_G1", send_auc_resp, NULL},
    {"LD_AUTHC_G2", finish_auc, NULL},
};

static const enum_names s_type_names = {AUC_RQST, SN_SESSION_EST_RESP, s_type_name, NULL};
static const enum_names pid_names = {PID_RESERVED, PID_BOTH, pid_name, NULL};
static const enum_names key_type_names = {ROOT_KEY, GROUP_KEY_CC, type_names, NULL};
static const enum_names authc_maclen_names = {AUTHC_MACLEN_INVALID, AUTHC_MACLEN_256, authc_maclen_name, NULL};
static const enum_names authc_auth_names = {AUTHC_AUTH_INVALID, AUTHC_AUTH_SM2_WITH_SM3, authc_authid_name, NULL};
static const enum_names authc_enc_names = {AUTHC_ENC_INVALID, AUTHC_ENC_SM4_CTR, authc_enc_name, NULL};
static const enum_names authc_klen_names = {AUTHC_KLEN_128, AUTHC_KLEN_256, authc_klen_name, NULL};

/**
 * AUC-RQST
 */
static field_desc auc_rqst_fields[] = {
    {ft_enum, S_TYP_LEN, "S_TYP", &s_type_names},
    {ft_set, VER_LEN, "VER", NULL},
    {ft_enum, PID_LEN, "PID", &pid_names},
    {ft_set, SAC_LEN, "AS_SAC", NULL},
    {ft_set, SAC_LEN, "GS_SAC", NULL},
    {ft_enum, AUTHC_ALG_S_LEN, "MAC_LEN", &authc_maclen_names},
    {ft_enum, AUTHC_ALG_S_LEN, "AUTH_ID", &authc_auth_names},
    {ft_enum, AUTHC_ALG_S_LEN, "ENC_ID", &authc_enc_names},
    {ft_fl_str, 0, "N1", &(pk_fix_length_t){.len = NONCE_LEN}},
    {ft_pad, 0, "PAD", NULL},
    {ft_end, 0, NULL, NULL},
};

struct_desc_t auc_rqst_desc = {"AUC_RQST", auc_rqst_fields};
/**
 * AUC-RESP
 */
static field_desc auc_resp_fields[] = {
    {ft_enum, S_TYP_LEN, "S_TYP", &s_type_names},
    {ft_set, VER_LEN, "VER", NULL},
    {ft_enum, PID_LEN, "PID", &pid_names},
    {ft_set, SAC_LEN, "AS_SAC", NULL},
    {ft_set, SAC_LEN, "GS_SAC", NULL},
    {ft_enum, AUTHC_ALG_S_LEN, "MAC_LEN", &authc_maclen_names},
    {ft_enum, AUTHC_ALG_S_LEN, "AUTH_ID", &authc_auth_names},
    {ft_enum, AUTHC_ALG_S_LEN, "ENC_ID", &authc_enc_names},
    {ft_enum, AUTHC_KLEN_LEN, "KLEN", &authc_klen_names},
    {ft_pad, 0, "PAD", NULL},
    {ft_fl_str, 0, "N2", &(pk_fix_length_t){.len = NONCE_LEN}},
    {ft_end, 0, NULL, NULL},
};

struct_desc_t auc_resp_desc = {"AUC_RESP", auc_resp_fields};
/**
 * AUC-KEY-EXEC
 */
static field_desc auc_key_exec_fields[] = {
    {ft_enum, S_TYP_LEN, "S_TYP", &s_type_names},
    {ft_set, VER_LEN, "VER", NULL},
    {ft_enum, PID_LEN, "PID", &pid_names},
    {ft_set, SAC_LEN, "AS_SAC", NULL},
    {ft_set, SAC_LEN, "GS_SAC", NULL},
    {ft_enum, AUTHC_ALG_S_LEN, "MAC_LEN", &authc_maclen_names},
    {ft_enum, AUTHC_ALG_S_LEN, "AUTH_ID", &authc_auth_names},
    {ft_enum, AUTHC_ALG_S_LEN, "ENC_ID", &authc_enc_names},
    {ft_fl_str, 0, "N3", &(pk_fix_length_t){.len = NONCE_LEN}},
    {ft_pad, 0, "PAD", NULL},
    {ft_end, 0, NULL, NULL},
};
struct_desc_t auc_key_exec_desc = {"AUC_KEY_EXEC", auc_key_exec_fields};

static field_desc key_upd_rqst_fields[] = {
    {ft_enum, S_TYP_LEN, "S_TYP", &s_type_names},
    {ft_set, VER_LEN, "VER", NULL},
    {ft_enum, PID_LEN, "PID", &pid_names},
    {ft_set, SAC_LEN, "AS_SAC", NULL},
    {ft_enum, KEY_TYPE_LEN, "KEY_TYPE", &key_type_names},
    {ft_set, SAC_LEN, "GS_SAC_SRC", NULL},
    {ft_set, SAC_LEN, "GS_SAC_DST", NULL},
    {ft_set, NCC_LEN, "NCC", NULL},
    {ft_fl_str, 0, "NONCE", &(pk_fix_length_t){.len = NONCE_LEN}},
    {ft_pad, 0, "PAD", NULL},
    {ft_end, 0, NULL, NULL},
};
struct_desc_t key_upd_rqst_desc = {"KEY_UPDATE_REQUEST", key_upd_rqst_fields};

static field_desc key_upd_resp_fields[] = {
    {ft_enum, S_TYP_LEN, "S_TYP", &s_type_names},
    {ft_set, VER_LEN, "VER", NULL},
    {ft_enum, PID_LEN, "PID", &pid_names},
    {ft_set, SAC_LEN, "AS_SAC", NULL},
    {ft_enum, KEY_TYPE_LEN, "KEY_TYPE", &key_type_names},
    {ft_set, SAC_LEN, "GS_SAC_DST", NULL},
    {ft_set, NCC_LEN, "NCC", NULL},
    {ft_pad, 0, "PAD", NULL},
    {ft_end, 0, NULL, NULL},
};

struct_desc_t key_upd_resp_desc = {"KEY_UPDATE_RESPONSE", key_upd_resp_fields};

static field_desc sn_session_est_rqst_fields[] = {
    {ft_set, 8, "SN_TYP", NULL},
    {ft_set, 3, "VER", NULL},
    {ft_set, 2, "PID", NULL},
    {ft_pad, 0, "PAD", NULL},
    {ft_set, 12, "SAC", NULL},
    {ft_set, 4, "SERVICE TYPE", NULL},
    {ft_pad, 0, "PAD", NULL},
    {ft_end, 0, NULL, NULL},
};

struct_desc_t sn_session_est_rqst_desc = {"SN_SESSION_EST_RQST", sn_session_est_rqst_fields};

static field_desc sn_session_est_resp_fields[] = {
    {ft_set, 8, "SN_TYP", NULL},
    {ft_set, 3, "VER", NULL},
    {ft_set, 2, "PID", NULL},
    {ft_pad, 0, "PAD", NULL},
    {ft_set, 12, "SAC", NULL},
    {ft_pad, 0, "PAD", NULL},
    {ft_fl_str, 0, "IP", &(pk_fix_length_t){.len = IPV6_ADDRLEN >> 3}},
    {ft_pad, 0, "PAD", NULL},
    {ft_end, 0, NULL, NULL},
};

struct_desc_t sn_session_est_resp_desc = {"SN_SESSION_EST_RESP", sn_session_est_resp_fields};

static field_desc failed_message_fields[] = {
    {ft_set, 8, "SN_TYP", NULL},
    {ft_set, 3, "VER", NULL},
    {ft_set, 2, "PID", NULL},
    {ft_set, 12, "SAC", NULL},
    {ft_set, 4, "FAILED TYPE", NULL},
    {ft_pad, 0, "PAD", NULL},
    {ft_dl_str, 0, "MSG", NULL},
    {ft_end, 0, NULL, NULL},
};

struct_desc_t failed_message_desc = {"FAILED_MESSGAE", failed_message_fields};

static field_desc gsg_sac_pkt_fields[] = {
    {ft_set, 4, "TYPE", NULL},
    {ft_set, 28, "UA", NULL},
    {ft_pad, 0, "PAD", NULL},
    {ft_dl_str, 0, "SDU", NULL},
    {ft_end, 0, NULL, NULL},
};

struct_desc_t gsg_sac_pkt_desc = {"GSG SAC PKT", gsg_sac_pkt_fields};

static field_desc gsg_pkt_fields[] = {
    {ft_set, 4, "TYPE", NULL},
    {ft_set, 12, "SAC", NULL},
    {ft_pad, 0, "PAD", NULL},
    {ft_dl_str, 0, "SDU", NULL},
    {ft_end, 0, NULL, NULL},
};
struct_desc_t gsg_pkt_desc = {"GSG PKT", gsg_pkt_fields};

static field_desc gsg_as_exit_fields[] = {
    {ft_set, 4, "TYPE", NULL},
    {ft_set, 12, "AS SAC", NULL},
    {ft_pad, 0, "PAD", NULL},
    {ft_end, 0, NULL, NULL},
};
struct_desc_t gsg_as_exit_desc = {"GSNF STATE CHANGE", gsg_as_exit_fields};

static field_desc gsnf_pkt_cn_fields[] = {
    {ft_set, 8, "G_TYP", NULL},
    {ft_set, 4, "VER", NULL},
    {ft_set, 12, "SAC", NULL},
    {ft_set, 4, "ELE_TYPE", NULL},
    {ft_pad, 0, "PAD", NULL},
    {ft_dl_str, 0, "SDU", NULL},
    {ft_end, 0, NULL, NULL},
};
struct_desc_t gsnf_pkt_cn_desc = {"GSNF PKT", gsnf_pkt_cn_fields};

static field_desc gsnf_pkt_cn_ini_fields[] = {
    {ft_set, 8, "G_TYP", NULL},
    {ft_set, 4, "VER", NULL},
    {ft_set, 12, "SAC", NULL},
    {ft_set, 4, "ELE_TYPE", NULL},
    {ft_set, 28, "UA", NULL},
    {ft_pad, 0, "PAD", NULL},
    {ft_dl_str, 0, "SDU", NULL},
    {ft_end, 0, NULL, NULL},
};
struct_desc_t gsnf_pkt_cn_ini_desc = {"GSNF INITIAL AS PKT", gsnf_pkt_cn_ini_fields};

static field_desc gsnf_as_auz_info_fields[] = {
    {ft_set, 8, "G_TYP", NULL},
    {ft_set, 4, "VER", NULL},
    {ft_set, 12, "SAC", NULL},
    {ft_set, 4, "IS LEGAL", NULL},
    {ft_set, 4, "AUZ TYPE", NULL},
    {ft_pad, 0, "PAD", NULL},
    {ft_end, 0, NULL, NULL},
};
struct_desc_t gsnf_as_auz_info_desc = {"GSNF AS AUZ INFO PKT", gsnf_as_auz_info_fields};


static field_desc gsnf_st_chg_fields[] = {
    {ft_set, 8, "G_TYP", NULL},
    {ft_set, 4, "VER", NULL},
    {ft_set, 12, "AS SAC", NULL},
    {ft_set, 4, "STATE", NULL},
    {ft_set, 12, "GS SAC", NULL},
    {ft_pad, 0, "PAD", NULL},
    {ft_end, 0, NULL, NULL},
};
struct_desc_t gsnf_st_chg_desc = {"GSNF STATE CHANGE", gsnf_st_chg_fields};


static field_desc gs_sac_resp_fields[] = {
    {ft_set, 12, "SAC", NULL},
    {ft_pad, 0, "PAD", NULL},
    {ft_end, 0, NULL, NULL},
};

struct_desc_t gs_sac_resp_desc = {"GS SAC RESP", gs_sac_resp_fields};

static field_desc gs_key_trans_fields[] = {
    {ft_dl_str, 0, "KEY", NULL},
    {ft_dl_str, 0, "NONCE", NULL},
    {ft_end, 0, NULL, NULL},
};

struct_desc_t gs_key_trans_desc = {"KEY_TRANS_DESC", gs_key_trans_fields};
