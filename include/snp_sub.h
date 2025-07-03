//
// Created by 邹嘉旭 on 2025/3/28.
//

#ifndef SNP_SUB_H
#define SNP_SUB_H

#include "ldcauc.h"

#define MAX_SNP_SDU_LEN 2012
#define MAX_SNP_PDU_LEN 2048
#define SNP_RANGE 10

enum SNP_ERRORS {
    /* Verify */
    VER_PASS = 0x00,
    VER_WRONG_MAC = 0xE1,
    VER_WRONG_SQN = 0xE2,
};


#endif //SNP_SUB_H
