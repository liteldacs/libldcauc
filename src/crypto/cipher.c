//
// Created by 邹嘉旭 on 2024/4/20.
//

#include "crypto/cipher.h"
#include <gmssl/sm4.h>
#include <gmssl/sm3.h>

l_err encrypt_uint8(void *key, uint8_t *in, size_t in_len, uint8_t *out, size_t *out_len) {
    uint8_t iv[16] = {0};
#ifdef USE_CRYCARD
    km_encrypt(key, ALGO_ENC_AND_DEC, iv, in, in_len, out, (uint32_t *)out_len, TRUE);

    uint8_t plain[128] = {0};
    uint32_t sz = 0;
    km_decrypt(key, ALGO_ENC_AND_DEC, iv, out, *out_len, plain, &sz, TRUE);

#else
    SM4_KEY sm4_key;
    sm4_set_encrypt_key(&sm4_key, key);
    if (!sm4_cbc_padding_encrypt(&sm4_key, iv, in, in_len, out, out_len)) {
        log_error("Encrypt Failed");
        return LD_ERR_INTERNAL;
    }
#endif
    return LD_OK;
}

l_err decrypt_uint8(void *key, uint8_t *in, size_t in_len, uint8_t *out, size_t *out_len) {
    uint8_t iv[16] = {0};
#ifdef USE_CRYCARD
    km_decrypt(key, ALGO_ENC_AND_DEC, iv, in, in_len, out, (uint32_t *)out_len, TRUE);
//    memcpy(out, in, in_len);
//    *out_len = in_len;
#else
    SM4_KEY sm4_key;
    sm4_set_decrypt_key(&sm4_key, key);
    if (!sm4_cbc_padding_decrypt(&sm4_key, iv, in, in_len, out, out_len)) {
        log_error("Decrypt Failed");
        return LD_ERR_INTERNAL;
    }
#endif
    return LD_OK;
}


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
    if(km_hmac_with_keyhandle(key_med, udata, data_len, mac_buf, &hmac_len) != LD_KM_OK){
        log_warn("Cant calc hmac");
    }
#elif UNUSE_CRYCARD
    buffer_t *key = key_med;
    ld_sm3_hmac(key->ptr, key->len, udata, data_len, mac_buf);
#endif

    memcpy(mac_dst, mac_buf, mac_limit);
}

void calc_hmac_buffer(buffer_t *bdata, void *key_med, buffer_t *mac_dst, size_t mac_limit) {
    uint8_t mac_buf[32] = {0};
    //    calc_hmac_uint(bdata->ptr, bdata->len, key_med, mac_buf, mac_limit);
    CLONE_TO_CHUNK(*mac_dst, mac_buf, mac_limit);
}

bool verify_hmac_uint(void *key_med, uint8_t *to_verify, uint8_t *udata, size_t data_len, size_t mac_limit) {
    uint8_t mac_buf[32] = {0};
    calc_hmac_uint(udata, data_len, key_med, mac_buf, mac_limit);

    return !memcmp(to_verify, mac_buf, mac_limit);
}

bool verify_hmac_buffer(void *key_med, buffer_t *to_verify, buffer_t *bdata, size_t mac_limit) {
    //    return verify_hmac_uint(key_med, to_verify->ptr, bdata->ptr, bdata->len, mac_limit);
    return true;
}
