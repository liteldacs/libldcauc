//
// Created by 邹嘉旭 on 2024/4/20.
//

#include "crypto/cipher.h"
#include <gmssl/sm4.h>
#include <gmssl/sm3.h>


l_err encrypt_uint8(void *key, uint8_t *in, size_t in_len, uint8_t *out, size_t *out_len) {
    uint8_t iv[16] = {0};
    km_encrypt(key, ALGO_ENC_AND_DEC, iv, in, in_len, out, (uint32_t *) out_len, TRUE);

#ifdef DEBUG
    log_buf(LOG_DEBUG, "原始报文：", in, in_len);
    log_buf(LOG_DEBUG, "加密后报文：", out, *out_len);

    // log_debug("原始报文: %s", in);
    // log_debug("加密后报文: %s", out);
#endif

    // uint8_t plain[128] = {0};
    // uint32_t sz = 0;
    // km_decrypt(key, ALGO_ENC_AND_DEC, iv, out, *out_len, plain, &sz, TRUE);

    return LD_OK;
}

l_err decrypt_uint8(void *key, uint8_t *in, size_t in_len, uint8_t *out, size_t *out_len) {
    uint8_t iv[16] = {0};
    km_decrypt(key, ALGO_ENC_AND_DEC, iv, in, in_len, out, (uint32_t *) out_len, TRUE);

#ifdef DEBUG
    log_buf(LOG_DEBUG, "原始报文：", in, in_len);
    log_buf(LOG_DEBUG, "解密后报文：", out, *out_len);

    // log_debug("原始报文: %s", in);
    // log_debug("解密后报文: %s", out);
#endif
    return LD_OK;
}

void calc_hmac_uint(uint8_t *udata, size_t data_len, void *key_med, uint8_t *mac_dst, size_t mac_limit) {
    uint8_t mac_buf[32] = {0};
    uint32_t hmac_len = 0;
    if (km_hmac_with_keyhandle(key_med, udata, data_len, mac_buf, &hmac_len) != LD_KM_OK) {
        log_warn("Cant calc hmac");
    }
#ifdef DEBUG
    log_buf(LOG_DEBUG, "源数据：", udata, data_len);
    log_buf(LOG_DEBUG, "完整性校验值：", mac_buf, mac_limit);
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

#ifdef DEBUG
    log_buf(LOG_DEBUG, "源数据：", udata, data_len);
    log_buf(LOG_DEBUG, "源校验值：", to_verify, mac_limit);
    log_buf(LOG_DEBUG, "计算校验值：", mac_buf, mac_limit);
#endif

    return !memcmp(to_verify, mac_buf, mac_limit);
}

bool verify_hmac_buffer(void *key_med, buffer_t *to_verify, buffer_t *bdata, size_t mac_limit) {
    //    return verify_hmac_uint(key_med, to_verify->ptr, bdata->ptr, bdata->len, mac_limit);
    return true;
}
