//
// Created by 邹嘉旭 on 2024/4/20.
//

#ifndef CIPHER_H
#define CIPHER_H

#include "secure_core.h"

l_err encrypt_buf(buffer_t *p_buf, buffer_t *key, buffer_t *e_buf);

l_err decrypt_buf(buffer_t *e_buf, buffer_t *key, buffer_t *p_buf);

void calc_hmac_uint(uint8_t *udata, size_t data_len, void *key_med, uint8_t *mac_dst, size_t mac_limit);

void calc_hmac_buffer(buffer_t *bdata, void *key_med, buffer_t *mac_dst, size_t mac_limit);

bool verify_hmac_uint(void *key_med, uint8_t *to_verify, uint8_t *udata, size_t data_len, size_t mac_limit);

bool verify_hmac_buffer(void *key_med, buffer_t *to_verify, buffer_t *bdata, size_t mac_limit);

#endif //CIPHER_H
