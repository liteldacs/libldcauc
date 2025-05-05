//
// Created by root on 5/23/24.
//

#ifndef LDACS_SIM_KEY_H
#define LDACS_SIM_KEY_H

#include "secure_core.h"
#include <kmdb.h>


#pragma pack(1)
#pragma pack()


//l_km_err get_rootkey(KEY_HANDLE *rootkey_handle);
//
//void gmssl_kdf(buffer_t *src, KEY_HANDLE *key_handle, size_t key_sz);
//
//void key_derive(KEY_HANDLE kdk_handle, enum KEY_TYPE key_type, uint32_t keylen, uint8_t *rand, uint32_t randlen,
//                KEY_HANDLE *key_handle, const char *owner1, const char *owner2);

l_km_err embed_rootkey(ldacs_roles role, const char *as_ua, const char *sgw_ua);

//l_km_err key_derive_as_sgw(ldacs_roles role, uint8_t *rand, uint32_t randlen, const char *as_ua,
//                           const char *gs_ua, const char *sgw_ua, KEY_HANDLE*key_ag);

//l_km_err key_install(buffer_t *key_ag, const char *as_ua, const char *gs_ua, uint8_t *nonce, uint32_t nonce_len,
//                     KEY_HANDLE*handle);

l_km_err key_get_handle(ldacs_roles role, const char *owner1, const char *owner2, enum KEY_TYPE key_type,
                        KEY_HANDLE*handle);

/**
* for AS : derive Kas-sgw and Kas-gs
*/
l_km_err as_derive_keys(uint8_t *rand, uint32_t randlen, const char *as_ua,
                        const char *gs_ua, const char *sgw_flag, KEY_HANDLE*key_aw, KEY_HANDLE*key_ag);

/**
* for GS : install SGW-sent raw Kas-gs
*/
l_km_err gs_install_keys(buffer_t *ag_raw, uint8_t *rand, uint32_t randlen, const char *as_ua,
                         const char *gs_ua, KEY_HANDLE*key_ag);

/**
* for SGW : derive Kas-sgw and derive raw Kas-gs
*/
l_km_err sgw_derive_keys(uint8_t *rand, uint32_t randlen, const char *as_ua,
                         const char *gs_ua, const char *sgw_ua, KEY_HANDLE *key_aw, buffer_t **kbuf);

l_km_err as_update_mkey(const char *sgw_ua, const char *gs_s_ua, const char *gs_t_ua, const char *as_ua,
                        buffer_t *nonce, KEY_HANDLE*key_as_gs);


#endif //LDACS_SIM_KEY_H
