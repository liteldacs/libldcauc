//
// Created by 邹嘉旭 on 2025/5/4.
//


#include <key_manage.h>
#include <ld_log.h>
#include "crypto/key.h"

static char *e_get_db_name(ldacs_roles role, const char *ua) {
    char *buf_dir = calloc(PATH_MAX, sizeof(char));
    char *db_name = NULL;
    // char *home_dir = get_home_dir();
    //
    // snprintf(buf_dir, PATH_MAX, "%s%s", home_dir, BASE_PATH);

    snprintf(buf_dir, PATH_MAX, "%s%s", get_home_dir(), BASE_PATH);
    if (check_path(buf_dir) != LD_OK) {
        free(buf_dir);
        // free(home_dir);
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
            // free(home_dir);
            return NULL;
    }
    snprintf(buf_dir, PATH_MAX, "%s%s%s_%s.db", get_home_dir(), BASE_PATH, db_name, ua);
    // snprintf(buf_dir, PATH_MAX, "%s%s", buf_dir, db_name);
    //
    // free(home_dir);
    return buf_dir;
}



//#define HOME_DIR "/root/"
#define HOME_DIR "/home/jiaxv/"


const size_t as_count = 40;
static const char *default_ASs[] = {
    "001012345",
    "001022345",
    "001032345",
    "001042345",
    "001052345",
    "001062345",
    "001072345",
    "001082345",
    "001092345",
    "001102345",
    "001112345",
    "001122345",
    "001132345",
    "001142345",
    "001152345",
    "001162345",
    "001172345",
    "001182345",
    "001192345",
    "001202345",
    "001212345",
    "001222345",
    "001232345",
    "001242345",
    "001252345",
    "001262345",
    "001272345",
    "001282345",
    "001292345",
    "001302345",
    "001312345",
    "001322345",
    "001332345",
    "001342345",
    "001352345",
    "001362345",
    "001372345",
    "001382345",
    "001392345",
    "001402345",
};

bool is_SGW = FALSE;

int8_t generate_rkey();

int8_t write_rkey_tocard(void);

static void usage(const char *executable) {
    printf("Usage: %s [-c config path] "
           "[-H (http mode)] [-M (Merge mode)]\n",
           executable);
}


int opt_parse(int argc, char *const *argv) {
    int c;
    while ((c = getopt(argc, argv, "as")) != -1) {
        switch (c) {
            case 'a':
                is_SGW = FALSE;
                write_rkey_tocard();
                break;
            case 's':
                is_SGW = TRUE;
                generate_rkey();
                write_rkey_tocard();
                break;
            // case 't': {
            //     config.timeout = strtol(optarg, NULL, 10);
            //     break;
            // }
            // case 'w': {
            //     config.worker = strtol(optarg, NULL, 10);
            //     if (config.worker > sysconf(_SC_NPROCESSORS_ONLN)) {
            //         fprintf(stderr,
            //                 "Config ERROR: worker num greater than cpu available cores.\n");
            //         return ERROR;
            //     }
            //     break;
            // }
            // case 'c': {
            //     memcpy(config.config_path, optarg, strlen(optarg));
            //     if (init_config_path() != OK) {
            //         return ERROR;
            //     }
            //     parse_config(&config, config.config_path);
            //     break;
            // }
            // case 'A':
            // case 'G':
            // case 'W': {
            //     if (config.role != LD_UNDEFINED) {
            //         return ERROR;
            //     }
            //     switch (c) {
            //         case 'A':
            //             config.role = LD_AS;
            //             break;
            //         case 'G':
            //             config.role = LD_GS;
            //             break;
            //         case 'W':
            //             config.role = LD_SGW;
            //             break;
            //         default:
            //             return ERROR;
            //     }
            //     if (init_config_path() != OK) {
            //         return ERROR;
            //     }
            //     parse_config(&config, config.config_path);
            // }
            // case 'H': {
            //     config.use_http = TRUE;
            //     break;
            // }
            // case 'M': {
            //
            //     if (config.role == LD_SGW) {
            //         config.port = strtol("55551", NULL, 10);
            //     }
            //     config.is_merged = TRUE;
            //     break;
            // }
            default: {
                return ERROR;
            }
        }
    }
    return OK;
}


int main(int argc, char **argv) {
#ifdef UNUSE_CRYCARD
    generate_kek(1);
#endif
    if (argc < 2 || opt_parse(argc, argv) != OK) {
        usage(argv[0]);
        exit(ERROR);
    }

    // #ifdef UNUSE_CRYCARD
    //     generate_kek(1);
    // #endif
    //     char *db_name = e_get_db_name(LD_SGW);
    //     char *table_name = get_table_name(LD_SGW);
    //     if (km_rkey_gen_export("000010010", "000010000", ROOT_KEY_LEN, DEFAULT_VALIDATE, db_name, table_name,
    //                            HOME_DIR".ldcauc/keystore/000010010_rootkey.bin")) {
    //         log_error("根密钥生成、保存和导出失败。");
    //     }
    //     if (km_rkey_gen_export("000045678", "000010000", ROOT_KEY_LEN, DEFAULT_VALIDATE, db_name, table_name,
    //                            HOME_DIR".ldcauc/keystore/000045678_rootkey.bin")) {
    //         log_error("根密钥生成、保存和导出失败。");
    //     }
}


int8_t generate_rkey() {
    char *db_name = e_get_db_name(LD_SGW, "000010000");

    for (int i = 0; i < as_count; i++) {
        char *buf_dir = calloc(PATH_MAX, sizeof(char));
        snprintf(buf_dir, PATH_MAX, HOME_DIR".ldcauc/keystore/%s_rootkey.bin", default_ASs[i]);
        if (km_rkey_gen_export(default_ASs[i], "000010000", ROOT_KEY_LEN, DEFAULT_VALIDATE, db_name, SGW_KEY_TABLE,
                               buf_dir)) {
            log_error("根密钥生成、保存和导出失败。 %s", default_ASs[i]);
            free(db_name);
            free(buf_dir);
            return -1;
        }

        QueryResult_for_queryid *qr_mk = query_id(db_name, SGW_KEY_TABLE, default_ASs[i], "000010000", ROOT_KEY, PRE_ACTIVATION);
        if (qr_mk->count == 0) {
            log_error("Query mkid failed.\n");
            return -1;
        }

        enable_key(db_name, SGW_KEY_TABLE, qr_mk->ids[0]);
        free(buf_dir);
        log_info("Generate Rootkey for %s has Succeed", default_ASs[i]);
    }
    free(db_name);
    return 0;
}

int8_t write_rkey_tocard(void) {
    // char *db_name = e_get_db_name(is_SGW ? LD_SGW : LD_AS);

    for (int i = 0; i < as_count; i++) {
        char *dir_buf = calloc(PATH_MAX, sizeof(char));
        snprintf(dir_buf, PATH_MAX, HOME_DIR".ldcauc/keystore/%s_rootkey.bin", default_ASs[i]);
        char *file_buf = calloc(PATH_MAX, sizeof(char));
        snprintf(file_buf, PATH_MAX, "%s_rootkey.bin", default_ASs[i]);
        if (km_writefile_to_cryptocard(dir_buf, file_buf) !=
            LD_KM_OK) {
            log_error("Error writing to ccard. %s", default_ASs[i]);
            free(dir_buf);
            free(file_buf);
            // free(db_name);
            return -1;
        }
        free(dir_buf);
        free(file_buf);
        log_info("Install Rootkey for %s Has Succeed", default_ASs[i]);
    }
    // free(db_name);
    return 0;
}
