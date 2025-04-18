//
// Created by root on 5/23/24.
//

#include "crypto/key.h"

static char *get_db_name(ldacs_roles role) {
//    log_error("%s%s%s", get_home_dir(), BASE_PATH, ROOT_KEY_BIN_PATH);
    char *buf_dir = calloc(PATH_MAX, sizeof (char ));
    char *db_name = NULL;

    snprintf(buf_dir, PATH_MAX, "%s%s", get_home_dir(), BASE_PATH);
    if(check_path(buf_dir) != LD_OK) {
        free(buf_dir);
        return NULL;
    }

    switch (role) {
        case LD_AS:
            db_name = AS_DB_NAME;
            break;
        case LD_GS:
            db_name = GS_DB_NAME;
            break;
        case LD_SGW:
            db_name = SGW_DB_NAME;
            break;
        default:
            free(buf_dir);
            return NULL;
    }
    snprintf(buf_dir, PATH_MAX, "%s%s%s", get_home_dir(), BASE_PATH, db_name);


    return buf_dir;
}

static char *get_table_name(ldacs_roles role) {
    switch (role) {
        case LD_AS:
            return AS_KEY_TABLE;
        case LD_GS:
            return GS_KEY_TABLE;
        case LD_SGW:
            return SGW_KEY_TABLE;
        default:
            return NULL;
    }
}


#define KDF_ITER 10000
#ifdef USE_CRYCARD
/* for AS / SGW */
static l_km_err key_derive_as_sgw(ldacs_roles role, uint8_t *rand, uint32_t randlen, const char *as_ua,
                           const char *gs_ua, const char *sgw_ua, KEY_HANDLE *key_aw) {
    char *db_name = get_db_name(role);
    char *table_name = get_table_name(role);

    l_km_err err = LD_KM_OK;
    QueryResult_for_queryid *qr_rk = query_id(db_name, table_name, as_ua, sgw_ua, ROOT_KEY, ACTIVE);
    if (qr_rk == NULL || qr_rk->count == 0) {
        log_error("Query mkid failed.\n");
        free(db_name);
        err = LD_ERR_KM_QUERY;
        goto cleanup;
    }

    /* 派生AS_GS主密钥, derive_key中根据key id查出来的key类型进行派生，默认派生了Kas-sgw和Kas-gs */
    uint32_t len_kassgw = 16;
    if ((err = km_derive_key(db_name, table_name, qr_rk->ids[0], len_kassgw, gs_ua, rand, randlen)) !=
        LD_KM_OK) {
        log_error("[**Derive master key error**]\n");
        goto cleanup;
    }

    /* 派生Kas-gs后，数据库查询 */
    QueryResult_for_queryid *qr_mk = query_id(db_name, table_name, as_ua, sgw_ua, MASTER_KEY_AS_SGW, ACTIVE);
    if (qr_mk->count == 0) {
        log_error("Query mkid failed.\n");
        free(db_name);
        err = LD_ERR_KM_QUERY;
        goto cleanup;
    }

    if ((err = get_handle_from_db(db_name, table_name, qr_mk->ids[0], key_aw)) != LD_KM_OK) {
        log_error("Can not get handle");
        free(db_name);
        goto cleanup;
    }
cleanup:
    free(db_name);
    return err;
}

/**
 *
 */
static l_km_err key_install(buffer_t *key_ag, const char *as_ua, const char *gs_ua, uint8_t *nonce, uint32_t nonce_len,
                     KEY_HANDLE *handle) {
    l_km_err err = LD_KM_OK;

    char *db_name = get_db_name(LD_GS);
    const char *table_name = get_table_name(LD_GS);
    if((err = km_install_key(db_name, table_name, key_ag->len, key_ag->ptr, as_ua, gs_ua, nonce_len, nonce))!= LD_KM_OK){
        log_error("Cannot install key.\n");
        goto cleanup;
    }

    QueryResult_for_queryid *qr_mk = query_id(db_name, table_name, as_ua, gs_ua, MASTER_KEY_AS_GS, ACTIVE);
    if (qr_mk->count == 0) {
        log_error("Query mkid failed.\n");
        err = LD_ERR_KM_QUERY;
        goto cleanup;
    }

    if ((err = get_handle_from_db(db_name, table_name, qr_mk->ids[0], handle)) != LD_KM_OK) {
        log_error("Can not get handle");
        goto cleanup;
    }

cleanup:
    free(db_name);
    return err;
}

#elif UNUSE_CRYCARD
#include <gmssl/pbkdf2.h>
/** generate key by sm3 kdf, using gmssl lib */
static l_km_err gmssl_kdf(uint8_t *rand, size_t rand_len, KEY_HANDLE*handle, size_t key_sz) {
    *handle = init_buffer_unptr();
    buffer_t *key_buf = *handle;
    // SM3_KDF_CTX kdf_ctx;
    uint8_t salt[32] = {0};
    uint8_t kdf_str[32] = {0};

    pbkdf2_hmac_sm3_genkey(rand, rand_len, salt, 32, KDF_ITER, key_sz, kdf_str);

    CLONE_TO_CHUNK(*key_buf, kdf_str, key_sz);

    return LD_KM_OK;
}

#endif


l_km_err embed_rootkey(ldacs_roles role, const char *as_ua, const char *sgw_ua) {
    l_km_err err = LD_KM_OK;
#ifdef USE_CRYCARD

    char *db_name = get_db_name(role);
    const char *table_name = get_table_name(role);
    if (role == LD_AS || role == LD_GS) // AS从密码卡导入根密钥
    {
        if ((err = km_rkey_import(db_name, table_name, "rootkey.bin") !=
                   LD_KM_OK))
        {
            log_error("AS import rootkey failed\n");
            goto cleanup;
        }
    }
    else if (role == LD_SGW) // 网关生成并导出根密钥
    {
//        if (km_rkey_gen_export(as_ua, sgw_ua, ROOT_KEY_LEN, DEFAULT_VALIDATE, db_name, table_name,
//                               KEY_BIN_PATH))
//        {
//            log_error("根密钥生成、保存和导出失败。");
//        }
//        if (km_writefile_to_cryptocard(KEY_BIN_PATH, "rootkey.bin") != LD_KM_OK)
//        {
//            log_error("Error writing to ccard.");
//        }
        goto cleanup;
    }
    // 激活as端根密钥
    QueryResult_for_queryid *query_result_as = query_id(db_name, table_name, as_ua, sgw_ua, ROOT_KEY,
                                                        PRE_ACTIVATION);
    if (query_result_as != NULL)    {
        if ((err = enable_key(db_name, table_name, query_result_as->ids[0])) != LD_KM_OK)
        {
            log_error("enable key failed\n");
            goto cleanup;
        }
    }
    else    {
        log_error("query failed");
        err = LD_ERR_KM_QUERY; // 查询失败
        goto cleanup;
    }

cleanup:
    free(db_name);
#endif
    log_info("embed OK!");
    return err;
}

l_km_err as_derive_keys(uint8_t *rand, uint32_t randlen, const char *as_ua,
                        const char *gs_ua, const char *sgw_flag, KEY_HANDLE*key_aw, KEY_HANDLE*key_ag) {
    l_km_err err = LD_KM_OK;

#ifdef USE_CRYCARD
    if ((err = key_derive_as_sgw(LD_AS, rand, randlen, as_ua, gs_ua, sgw_flag, key_aw)) != LD_KM_OK) {
        log_error("Can not derive Kas-sgw");
        return err;
    }

    if ((err = key_get_handle(LD_AS, as_ua, gs_ua, MASTER_KEY_AS_GS, key_ag)) != LD_KM_OK) {
        log_error("Can not get handle");
        return err;
    }

#elif UNUSE_CRYCARD
    gmssl_kdf(rand, randlen, key_aw, ROOT_KEY_LEN);
    gmssl_kdf(rand, randlen, key_ag, ROOT_KEY_LEN);
#endif

    return err;
}

l_km_err gs_install_keys(buffer_t *ag_raw, uint8_t *rand, uint32_t randlen, const char *as_ua,
                         const char *gs_ua, KEY_HANDLE*key_ag) {
    l_km_err err = LD_KM_OK;
#ifdef USE_CRYCARD

    if ((err = key_install(ag_raw, as_ua, gs_ua, rand, randlen, key_ag)) != LD_KM_OK) {
        log_error("GS cannot install Kas-sgw");
        return err;
    }

#elif UNUSE_CRYCARD
    // err = gmssl_kdf(rand, randlen, key_ag, ROOT_KEY_LEN);
    *key_ag = init_buffer_unptr();
    buffer_t *key_ag_b = *key_ag;
    CLONE_TO_CHUNK(*key_ag_b, ag_raw->ptr, ag_raw->len);
    // log_buf(LOG_ERROR, "GS KEY", (*(buffer_t **)key_ag)->ptr, (*(buffer_t **)key_ag)->len);
#endif
    return err;
}

l_km_err sgw_derive_keys(uint8_t *rand, uint32_t randlen, const char *as_ua,
                         const char *gs_ua, const char *sgw_ua, KEY_HANDLE*key_aw, buffer_t **kbuf) {
    l_km_err err = LD_KM_OK;
#ifdef USE_CRYCARD

    char *db_name = get_db_name(LD_SGW);
    const char *table_name = get_table_name(LD_SGW);
    if ((err = key_derive_as_sgw(LD_SGW, rand, randlen, as_ua, gs_ua, sgw_ua, key_aw)) != LD_KM_OK) {
        log_error("Can not derive Kas-sgw");
        goto cleanup;
    }

    QueryResult_for_queryid *qr_mk = query_id(db_name, table_name, as_ua, gs_ua, MASTER_KEY_AS_GS, ACTIVE);
    if (qr_mk->count == 0) {
        log_error("Query mkid failed.\n");
        err = LD_ERR_KM_QUERY;
        goto cleanup;
    }

    QueryResult_for_keyvalue *result = query_keyvalue(db_name, table_name, qr_mk->ids[0]);
    if (!result) {
        log_error("Key not found or error occurred.\n");
        err = LD_ERR_KM_QUERY;
        goto cleanup;
    }
    CLONE_TO_CHUNK(**kbuf, result->key, result->key_len);

cleanup:
    free(db_name);
#elif UNUSE_CRYCARD

    err = gmssl_kdf(rand, randlen, key_aw, ROOT_KEY_LEN);
    err = gmssl_kdf(rand, randlen, (void *) kbuf, ROOT_KEY_LEN);
#endif
    return err;
}


l_km_err key_get_handle(ldacs_roles role, const char *owner1, const char *owner2, enum KEY_TYPE key_type,
                        KEY_HANDLE*handle) {
    l_km_err err = LD_KM_OK;
#ifdef USE_CRYCARD
    char *db_name = get_db_name(role);
    const char *table_name = get_table_name(role);
    QueryResult_for_queryid *qr_mk = query_id(db_name, table_name, owner1, owner2, key_type, ACTIVE);
    if (qr_mk->count == 0) {
        log_error("Query mkid failed. %s %s %s\n", table_name, owner1, owner2);
        err = LD_ERR_KM_QUERY;
        goto cleanup;
    }


    if ((err = get_handle_from_db(db_name, table_name, qr_mk->ids[0], handle)) != LD_KM_OK) {
        log_error("err:%08x", err);
        goto cleanup;
    }

    QueryResult_for_keyvalue *result = query_keyvalue(db_name, table_name, qr_mk->ids[0]);
    if (!result) {
        log_error("Key not found or error occurred.\n");
        err = LD_ERR_KM_QUERY;
        goto cleanup;
    }
cleanup:
    free(db_name);
#elif UNUSE_CRYCARD

    *handle = init_buffer_unptr();
    buffer_t *key_buf = *handle;
    /* 默认 [0,0,0,...,0] */
    uint8_t kdf_str[ROOT_KEY_LEN] = {0};

    CLONE_TO_CHUNK(*key_buf, kdf_str, ROOT_KEY_LEN);
#endif

    return err;
}

l_km_err as_update_mkey(const char *sgw_ua, const char *gs_s_ua, const char *gs_t_ua, const char *as_ua,
                        buffer_t *nonce, KEY_HANDLE*key_as_gs) {
    l_km_err err = LD_KM_OK;
#ifdef USE_CRYCARD
    char *db_name = get_db_name(LD_AS);
    const char *table_name = get_table_name(LD_AS);
    if(km_update_masterkey(db_name, table_name, sgw_ua, gs_s_ua, gs_t_ua, as_ua, nonce->len, nonce->ptr) != LD_KM_OK){
        log_error("Cannot update masterkey");
        err = LD_ERR_KM_UPDATE_SESSIONKEY;
    }
    free(db_name);
#elif UNUSE_CRYCARD
#endif
    return err;
}
