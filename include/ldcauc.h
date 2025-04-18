//
// Created by 邹嘉旭 on 2025/3/30.
//

#ifndef LDCAUC_H
#define LDCAUC_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define LDCAUC_OK (0)
#define LDCAUC_FAIL (-1)
#define LDCAUC_WRONG_PARA (-2)
#define LDCAUC_NULL (-3)
#define LDCAUC_INTERNAL_ERROR (-4)

#define ROLE_AS 1
#define ROLE_GS 2
#define ROLE_SGW 4

#define PROTECT_VERSION 1

enum SEC_ALG_MACLEN {
    SEC_MACLEN_INVAILD = 0x0,
    SEC_MACLEN_96 = 0x1,
    SEC_MACLEN_128 = 0x2,
    SEC_MACLEN_64 = 0x3,
    SEC_MACLEN_256 = 0x4,
};

#define get_sec_maclen(en)({    \
    int ret;                    \
    switch(en){                 \
        case 0x1:               \
            ret = 12;          \
            break;              \
        case 0x2:               \
            ret = 16;          \
            break;              \
        case 0x3:               \
            ret = 8;          \
            break;              \
        case 0x4:               \
            ret = 32;          \
            break;              \
        default:                \
            ret = 0;            \
            break;              \
    };                          \
    ret;        \
})

typedef int8_t (*finish_auth)();

typedef int8_t (*trans_snp)(uint16_t AS_SAC, uint16_t GS_SAC, uint8_t *buf, size_t buf_len);

typedef int8_t (*register_snf_fail)(uint16_t AS_SAC);

/**
 * \brief  AS初始化SNF层
 * @param[in] finish_auth   认证完成回调函数
 * @param[in] trans_snp     LME->SNP 回调函数
 */
void init_as_snf_layer(finish_auth finish_auth, trans_snp trans_snp, register_snf_fail register_fail);

/**
 * \brief  GS初始化SNF层
 * @param[in] GS_SAC        GS SAC
 * @param[in] gsnf_addr     GSC/网关IPv6地址
 * @param[in] trans_snp     LME->SNP 回调函数
 * @param[in] register_fail 注册失败回调
 */
void init_gs_snf_layer(uint16_t GS_SAC, const char *gsnf_addr, uint16_t gsnf_port, trans_snp trans_snp,
                       register_snf_fail register_fail);

void init_gs_snf_layer_unmerged(uint16_t GS_SAC, const char *gsnf_addr, uint16_t gsnf_port, trans_snp trans_snp,
                                register_snf_fail register_fail);

/**
 * \brief  网关初始化SNF层
 * @param[in] listen_port     监听端口
 */
void init_sgw_snf_layer(uint16_t listen_port);

/**
 * \brief  清理SNF层数据并释放对应内存
 */
int8_t destory_snf_layer();

/**
 * \brief AUTH状态转换流程(AS)
 * AS进入LME-AUTH状态时调用函数，该函数初始化AS唯一的SNF实体，并启动内部AUTHC流程
 * @param[in] role      角色（ROLE_AS、ROLE_GS、ROLE_SGW）
 * @param[in] AS_SAC    AS SAC
 * @param[in] AS_UA     AS UA
 * @param[in] GS_SAC    GS SAC
 */
int8_t snf_LME_AUTH(uint8_t role, uint16_t AS_SAC, uint32_t AS_UA, uint16_t GS_SAC);

/**
 * \brief 注册SNF实体（GS）
 * GS在收到RA的CELL RESP后，在SNF中注册飞机实体
 * @param role      角色宏定义（ROLE_AS、ROLE_GS）
 * @param AS_SAC    AS SAC
 * @param AS_UA     AS UA
 * @param GS_SAC    GS SAC
 * @return
 */
int8_t register_snf_en(uint8_t role, uint16_t AS_SAC, uint32_t AS_UA, uint16_t GS_SAC);

/**
 * \brief 注销SNF实体（GS）
 * @param AS_SAC AS SAC
 * @return
 */
int8_t unregister_snf_en(uint16_t AS_SAC);

/**
 * \brief LME向SNF上传控制数据
 * 当LME通过SN原语收到控制数据后，通过此函数触发对应SNF功能
 * @param[in] is_valid  SNP报文是否有效
 * @param[in] AS_SAC    AS SAC
 * @param[in] GS_SAC    GS SAC
 * @param[in] snp_buf   SNP报文
 * @param[in] buf_len   报文长度
 */
int8_t upload_snf(bool is_valid, uint16_t AS_SAC, uint16_t GS_SAC, uint8_t *snp_buf, size_t buf_len);

/**
 * \brief 产生至多64位随机数
 * @param rand_bits_sz  随机数比特长度
 * @return  返回随机数
 */
uint64_t generate_urand(size_t rand_bits_sz);

/**
 * \brief SNP SUB 加密/解密
 * @param[in] AS_SAC        AS SAC
 * @param[in] in            输入
 * @param[in] in_len        输入长度
 * @param[out] out          输出
 * @param[out] out_len      输出长度
 * @param[in] is_encrypt    是否为加密模式
 * @return
 */
int8_t snpsub_crypto(uint16_t AS_SAC, uint8_t *in, size_t in_len, uint8_t *out, size_t *out_len, bool is_encrypt);

/**
 * \brief SNP SUB 计算HMAC
 * @param[in] AS_SAC        AS SAC
 * @param[in] SEC           安全模式（HMAC长度）
 * @param[in] in            输入
 * @param[in] in_len        输入长度
 * @param[out] out          输出
 * @param[out] out_len      输出长度
 * @return
 */
int8_t snpsub_calc_hmac(uint16_t AS_SAC, uint8_t SEC, uint8_t *in, size_t in_len, uint8_t *out, size_t *out_len);

/**
 * \brief SNP SUB 验证HMAC
 * @param[in] AS_SAC        AS SAC
 * @param[in] SEC           安全模式（HMAC长度）
 * @param[in] snp_pdu       SNP PDU
 * @param[in] pdu_len       PDU长度
 * @return
 */
int8_t snpsub_vfy_hmac(uint16_t AS_SAC, uint8_t SEC, uint8_t *snp_pdu, size_t pdu_len);

#endif //LDCAUC_H
