//
// Created by 邹嘉旭 on 2024/4/20.
//

#include "crypto/cipher.h"


// l_err encrypt_buf(buffer_t *p_buf, buffer_t *key, buffer_t *e_buf) {
//     if (e_buf == NULL || p_buf == NULL || key == NULL) {
//         return LD_ERR_INTERNAL;
//     }
//     SM4_KEY sm4_key;
//     uint8_t iv[16] = {0};
//     uint8_t out[8192] = {0};
//     size_t outlen = 0;
//
//     sm4_set_encrypt_key(&sm4_key, key->ptr);
//     sm4_cbc_padding_encrypt(&sm4_key, iv, p_buf->ptr, p_buf->len, out, &outlen);
//     CLONE_TO_CHUNK(*e_buf, out, outlen);
//
//     return LD_OK;
// }
//
// l_err decrypt_buf(buffer_t *e_buf, buffer_t *key, buffer_t *p_buf) {
//     if (p_buf == NULL || e_buf == NULL || key == NULL) {
//         return LD_ERR_INTERNAL;
//     }
//     SM4_KEY sm4_key;
//     uint8_t iv[16] = {0};
//     uint8_t out[8192] = {0};
//     size_t outlen = 0;
//
//     sm4_set_decrypt_key(&sm4_key, key->ptr);
//     sm4_cbc_padding_decrypt(&sm4_key, iv, e_buf->ptr, e_buf->len, out, &outlen);
//     CLONE_TO_CHUNK(*p_buf, out, outlen);
//
//     return LD_OK;
// }

#ifdef UNUSE_CRYCARD
static void ld_sm3_hmac(const uint8_t *key, size_t key_len,
                        const uint8_t *data, size_t data_len,
                        uint8_t mac[SM3_HMAC_SIZE]) {
    SM3_HMAC_CTX ctx;
    sm3_hmac_init(&ctx, key, key_len);
    sm3_hmac_update(&ctx, data, data_len);
    sm3_hmac_finish(&ctx, mac);
}
#endif


void calc_hmac_uint(uint8_t *udata, size_t data_len, void *key_med, uint8_t *mac_dst, size_t mac_limit) {
    uint8_t mac_buf[32] = {0};
#ifdef USE_CRYCARD
    uint32_t hmac_len = 0;
    km_hmac_with_keyhandle(key_med, udata, data_len, mac_buf, &hmac_len);
#elif UNUSE_CRYCARD
    buffer_t *key = key_med;
    ld_sm3_hmac(key->ptr, key->len, udata, data_len, mac_buf);
#endif

    memcpy(mac_dst, mac_buf, mac_limit);
}

void calc_hmac_buffer(buffer_t *bdata, void *key_med, buffer_t *mac_dst, size_t mac_limit) {
    uint8_t mac_buf[32] = {0};
    calc_hmac_uint(bdata->ptr, bdata->len, key_med, mac_buf, mac_limit);
    CLONE_TO_CHUNK(*mac_dst, mac_buf, mac_limit);
}

bool verify_hmac_uint(void *key_med, uint8_t *to_verify, uint8_t *udata, size_t data_len, size_t mac_limit) {
    uint8_t mac_buf[32] = {0};
    calc_hmac_uint(udata, data_len, key_med, mac_buf, mac_limit);

    return !memcmp(to_verify, mac_buf, mac_limit);
}

bool verify_hmac_buffer(void *key_med, buffer_t *to_verify, buffer_t *bdata, size_t mac_limit) {
    return verify_hmac_uint(key_med, to_verify->ptr, bdata->ptr, bdata->len, mac_limit);
}
