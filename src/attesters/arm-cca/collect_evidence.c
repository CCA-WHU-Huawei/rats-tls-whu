/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <rats-tls/attester.h>
#include <rats-tls/log.h>
#include <stdio.h>
#include <string.h>

#if 0

#define CCA_REPORT_IN "/sys/kernel/config/tsm/report/report0/inblob"
#define CCA_REPORT_OUT "/sys/kernel/config/tsm/report/report0/outblob"
static unsigned long long CCA_challenge = 0x1234567890CCACCA;
uint8_t cca_quote[8192];

enclave_attester_err_t arm_cca_collect_evidence(enclave_attester_ctx_t *ctx,
					       attestation_evidence_t *evidence,
					       rats_tls_cert_algo_t algo, uint8_t *hash,
					       uint32_t hash_len)
{
	RTLS_DEBUG("ARM CCA collect evidence called, ctx %p, evidence %p, algo %d, hash %p\n", ctx, evidence, algo, hash);

	FILE *file = fopen(CCA_REPORT_IN, "w");
	if(file == NULL) {
		RTLS_DEBUG("ARM CCA REPORT IN file open failed.\n");
		return -1;
	} else {
		fprintf(file, CCA_challenge);
	}
	int result = fclose(file);
	if(result != 0) {
		RTLS_DEBUG("ARM CCA REPORT IN file close failed.\n");
		return -1;
	}

	file = fopen(CCA_REPORT_OUT, "r");
	if(file == NULL) {
		RTLS_DEBUG("ARM CCA REPORT OUT file open failed.\n");
		return -1;
	} else {
		fseek(file, 0, SEEK_END);  // 将文件指针定位到文件末尾
		long fileSize = ftell(file);  // 获取文件指针的位置，即文件大小
		fseek(file, 0, SEEK_SET);  // 将文件指针重新定位到文件开头

		size_t bytesRead = fread(cca_quote, 1, fileSize, file);  // 读取文件内容到数组中
    	cca_quote[bytesRead] = '\0';  // 在数组末尾添加 null 终止符，将其转换为字符串

    	// 处理读取的文件内容
    	RTLS_DEBUG("File content: %s\n\n\n", cca_quote);
	}

	memcpy(evidence->cca.quote, cca_quote, 8192);
	evidence->cca.quote_len = sizeof(evidence->cca.quote);
	snprintf(evidence->type, sizeof(evidence->type), "%s", "arm_cca");

	return ENCLAVE_ATTESTER_ERR_NONE;
}

#endif

#define CCA_REPORT_IN "/tmp/report0/inblob"
#define CCA_REPORT_OUT "/tmp/report0/outblob"
static unsigned long long CCA_challenge = 0x1234567890CCACCA;
uint8_t cca_quote[8192];

enclave_attester_err_t arm_cca_collect_evidence(
    enclave_attester_ctx_t *ctx, attestation_evidence_t *evidence,
    rats_tls_cert_algo_t algo, uint8_t *hash, uint32_t hash_len) {
  RTLS_DEBUG("ARM CCA collect evidence called, ctx %p, evidence %p, algo %d, "
             "hash %p\n",
             ctx, evidence, algo, hash);

  /*FILE *file = fopen(CCA_REPORT_IN, "w");
  if(file == NULL) {
          RTLS_DEBUG("ARM CCA REPORT IN file open failed.\n");
          return -1;
  } else {
          fprintf(file, CCA_challenge);
  }
  int result = fclose(file);
  if(result != 0) {
          RTLS_DEBUG("ARM CCA REPORT IN file close failed.\n");
          return -1;
  }
  */

  FILE *file = fopen(CCA_REPORT_OUT, "r");
  if (file == NULL) {
    RTLS_DEBUG("ARM CCA REPORT OUT file open failed.\n");
    return -1;
  } else {
    fseek(file, 0, SEEK_END);    // 将文件指针定位到文件末尾
    long fileSize = ftell(file); // 获取文件指针的位置，即文件大小
    fseek(file, 0, SEEK_SET);    // 将文件指针重新定位到文件开头

    size_t bytesRead =
        fread(cca_quote, 1, fileSize, file); // 读取文件内容到数组中
    cca_quote[bytesRead] = '\0'; // 在数组末尾添加 null 终止符，将其转换为字符串

    // 处理读取的文件内容
    RTLS_DEBUG("File content: %s\n\n\n", cca_quote);
  }

  memcpy(evidence->cca.quote, cca_quote, 8192);
  evidence->cca.quote_len = sizeof(evidence->cca.quote);
  snprintf(evidence->type, sizeof(evidence->type), "%s", "arm_cca");

  return ENCLAVE_ATTESTER_ERR_NONE;
}
