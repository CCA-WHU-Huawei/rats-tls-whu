/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <rats-tls/attester.h>
#include <rats-tls/log.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

uint8_t cca_quote[8192];

enclave_attester_err_t arm_cca_collect_evidence(enclave_attester_ctx_t *ctx,
					       attestation_evidence_t *evidence,
					       rats_tls_cert_algo_t algo, uint8_t *hash,
					       uint32_t hash_len)
{
	RTLS_DEBUG("ARM CCA collect evidence called, ctx %p, evidence %p, algo %d, hash %p\n", ctx, evidence, algo, hash);

    system("cca-workload-attestation passport -o rats-tls-ear.jwt");

    uint32_t fileSize;
    FILE *file = fopen("./rats-tls-ear.jwt", "r");/*  */
    
    if(file == NULL) 
    {
        RTLS_DEBUG("Veraison ear.jwt file open failed.\n");
        fclose(file);
        return -1;
    } 
    else 
    {
        fseek(file, 0, SEEK_END);  // 将文件指针定位到文件末尾
        fileSize = ftell(file);  // 获取文件指针的位置，即文件大小
        fseek(file, 0, SEEK_SET);  // 将文件指针重新定位到文件开头

        size_t bytesRead = fread(cca_quote, 1, fileSize, file);  // 读取文件内容到数组中
        cca_quote[bytesRead] = '\0';  // 在数组末尾添加 null 终止符，将其转换为字符串

        // 处理读取的文件内容
        RTLS_DEBUG("File content: %s\n\n\n", cca_quote);
    }

    memcpy(evidence->cca.quote, cca_quote, 8192);
    //evidence->cca.quote_len = sizeof(evidence->cca.quote);
    evidence->cca.quote_len = fileSize;
    snprintf(evidence->type, sizeof(evidence->type), "%s", "arm_cca");

    fclose(file);
    return ENCLAVE_ATTESTER_ERR_NONE;
}
