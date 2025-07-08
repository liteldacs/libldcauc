//
// Created by 邹嘉旭 on 2025/7/8.
//

#ifndef INSIDE_H
#define INSIDE_H
#include "ldcauc.h"


/**
 * \brief  GS初始化SNF层(合并GSC、内部接口)
 * @param[in] GS_SAC        GS SAC
 * @param[in] gsnf_addr     GSC IPv6地址
 * @param[in] gsnf_local_port
 * @param[in] trans_snp     LME->SNP 回调函数
 * @param[in] register_fail 注册失败回调函数
 * @param[in] gst_ho_complete_key     完成Handover 回调函数
 */
void init_gs_snf_layer_inside(uint16_t GS_SAC, char *gsnf_addr, uint16_t gsnf_remote_port, uint16_t gsnf_local_port,
                              trans_snp trans_snp, register_snf_fail register_fail,
                              gst_ho_complete_key gst_ho_complete_key);

int8_t inside_combine_sac_request(uint32_t UA);

int8_t inside_combine_sac_response(uint16_t SAC, uint32_t UA);

#endif //INSIDE_H
