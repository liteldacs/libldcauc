//
// Created by 邹嘉旭 on 2024/4/20.
//

#ifndef CIPHER_H
#define CIPHER_H

#include "secure_core.h"

l_err encrypt_uint8(void *key, uint8_t *in, size_t in_len, uint8_t *out, size_t *out_len);

l_err decrypt_uint8(void *key, uint8_t *in, size_t in_len, uint8_t *out, size_t *out_len);

void calc_hmac_uint(uint8_t *udata, size_t data_len, void *key_med, uint8_t *mac_dst, size_t mac_limit);

void calc_hmac_buffer(buffer_t *bdata, void *key_med, buffer_t *mac_dst, size_t mac_limit);

bool verify_hmac_uint(void *key_med, uint8_t *to_verify, uint8_t *udata, size_t data_len, size_t mac_limit);

bool verify_hmac_buffer(void *key_med, buffer_t *to_verify, buffer_t *bdata, size_t mac_limit);

#endif //CIPHER_H
