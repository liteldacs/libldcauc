//
// Created by 邹嘉旭 on 2025/3/28.
//

#ifndef SNP_SUB_H
#define SNP_SUB_H
#include "ldcauc.h"

#define MAX_SNP_SDU_LEN 2012
#define MAX_SNP_PDU_LEN 2048
#define SNP_RANGE 10

int8_t snpsub_crypto(uint16_t AS_SAC, char *in, size_t in_len, char *out, size_t *out_len, bool is_encrypt);

int8_t snpsub_calc_hmac(uint16_t AS_SAC, uint8_t SEC, char *in, size_t in_len, char *out, size_t *out_len);

int8_t snpsub_vfy_hmac(uint16_t AS_SAC, uint8_t SEC, char *in, size_t in_len, char *mac, size_t mac_len);

#endif //SNP_SUB_H
