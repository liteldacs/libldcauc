//
// Created by 邹嘉旭 on 2025/3/28.
//
#include <ld_log.h>

#include "snf.h"

int main(void) {
    log_init(LOG_DEBUG, "../log", "test");

    snf_args_t args = {
        .AS_UA = 10086,
        .AS_SAC = 1234,
        .AS_CURR_GS_SAC = 2345
    };

    init_snf_layer();
    int8_t ret = register_snf_entity(&args);

    ret = unregister_snf_entity(1234);
    destory_snf_layer();
}
