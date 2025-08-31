//
// Created by 邹嘉旭 on 2025/7/8.
//

#ifndef INSIDE_H
#define INSIDE_H
#include "ldcauc.h"

/**
 * @brief 内部接口
 * @param[in] AS_SAC 发送或接收的`AS`对应的SAC
 * @param[in] AS_UA 发送或接收的`AS`对应的UA
 * @return 错误码
 */
typedef int8_t (*inside_setup_entity)(uint16_t AS_SAC, uint32_t AS_UA);

/**
* @brief 用于GSS，Handover完成回调，应包含功能：1. 向AS 发送 HO CMD
 * @param[in] AS_SAC 进行切换的`AS`对应的SAC
 * @param[in] GS_SAC 进行切换的`GS`对应的SAC
 * @param[in] next_co 新的CO
 * @return 错误码
 */
typedef l_err (*gss_ho_complete_key)(uint16_t AS_SAC, uint16_t GS_SAC, uint16_t next_co);

/**
 * \brief  GS初始化SNF层(合并GSC、内部接口)
 * @param config
 * @param[in] trans_snp     LME->SNP 回调函数
 * @param[in] register_fail 注册失败回调函数
 * @param[in] gst_ho_complete_key     完成Handover 回调函数
 * @param setup_entity
 * @param gss_ho_complete_key
 */
void init_gs_snf_layer_inside(config_t *config,
                              trans_snp trans_snp, register_snf_fail register_fail,
                              gst_ho_complete_key gst_ho_complete_key, inside_setup_entity setup_entity,
                              gss_ho_complete_key gss_ho_complete_key);

int8_t inside_combine_sac_request(uint32_t UA);

int8_t inside_combine_update_user_msg(uint16_t AS_SAC, uint8_t *snp_buf, size_t buf_len);

int8_t direct_combine_send_ho_rqst(uint16_t SAC, uint16_t CO);

#endif //INSIDE_H
