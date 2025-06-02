//
// Created by 邹嘉旭 on 2025/5/4.
//


#include <key_manage.h>
#include <ld_log.h>
#include "crypto/secure_core.h"
#include "crypto/key.h"

char *get_db_name(ldacs_roles role) {
    //    log_error("%s%s%s", get_home_dir(), BASE_PATH, ROOT_KEY_BIN_PATH);
    char *buf_dir = calloc(PATH_MAX, sizeof(char));
    char *db_name = NULL;

    snprintf(buf_dir, PATH_MAX, "%s%s", get_home_dir(), BASE_PATH);
    if (check_path(buf_dir) != LD_OK) {
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

char *get_table_name(ldacs_roles role) {
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


int main(int argc, char **argv) {
#ifndef USE_CRYCARD
    generate_kek(1);
#endif
    char *db_name = get_db_name(LD_SGW);
    char *table_name = get_table_name(LD_SGW);
    if (km_rkey_gen_export("000010010", "000010000", ROOT_KEY_LEN, DEFAULT_VALIDATE, db_name, table_name,
                           "/home/jiaxv/.ldcauc/keystore/000010010_rootkey.bin")) {
        log_error("根密钥生成、保存和导出失败。");
    }
    if (km_rkey_gen_export("000045678", "000010000", ROOT_KEY_LEN, DEFAULT_VALIDATE, db_name, table_name,
                           "/home/jiaxv/.ldcauc/keystore/000045678_rootkey.bin")) {
        log_error("根密钥生成、保存和导出失败。");
    }
    if (km_writefile_to_cryptocard("/home/jiaxv/.ldcauc/keystore/000010010_rootkey.bin", "000010010_rootkey.bin") !=
        LD_KM_OK) {
        log_error("Error writing to ccard.");
    }
    if (km_writefile_to_cryptocard("/home/jiaxv/.ldcauc/keystore/000045678_rootkey.bin", "000045678_rootkey.bin") !=
        LD_KM_OK) {
        log_error("Error writing to ccard.");
    }
}
