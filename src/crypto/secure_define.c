//
// Created by 邹嘉旭 on 2024/8/19.
//

#include "crypto/secure_core.h"

/* TODO: 处理一下和km_src的关系 */
void generate_rand(uint8_t *rand, size_t len) {
    km_generate_random(rand, len);
}

/* generate a rand int, max size is 64bits (8 bytes) */
uint64_t generate_urand(size_t rand_bits_sz) {
    if (rand_bits_sz > SYSTEM_BITS) return 0;
    uint64_t ret = 0;

    uint8_t rand[8] = {0};
    generate_rand(rand, 8);

    for (int i = 0; i < 8; i++) {
        ret += rand[i] << (BITS_PER_BYTE * (7 - i));
    }
    return ret & 0xFFFFFFFF >> (SYSTEM_BITS - rand_bits_sz);
}

/* generate a unlimit rand array */
void generate_nrand(uint8_t *rand, size_t sz) {
    generate_rand(rand, sz);
}

