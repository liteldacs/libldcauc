//
// Created by 邹嘉旭 on 2025/3/28.
//
#include <ld_log.h>

#include "snf.h"

int main(void) {
    log_init(LOG_DEBUG, "../log", "test");

    init_as_snf_layer();
    int8_t ret = register_snf_en(&(snf_args_t){
        .role = ROLE_GS,
        .AS_UA = 10086,
        .AS_SAC = 1234,
        .AS_CURR_GS_SAC = 2345
    });

    ret = unregister_snf_en(1234);
    destory_snf_layer();
}
