/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <rats-tls/log.h>
#include <rats-tls/verifier.h>
#include <time.h>
// #include "sgx_error.h"
// #include "rtls_t.h"

/* Refer to explanation in sgx_la_collect_evidence */
uint8_t cca_quote[8192];
enclave_verifier_err_t arm_cca_verify_evidence(enclave_verifier_ctx_t *ctx,
					      attestation_evidence_t *evidence, uint8_t *hash,
					      uint32_t hash_len,
					      __attribute__((unused))
					      attestation_endorsement_t *endorsements)
{
	// CCA Verify
	FILE *fp;
	fp = fopen("received_ear.jwt", "wb");
    if (fp == NULL) {
        perror("fopen() error");
        return -1;
    }

	fwrite(evidence->cca.quote, 1, evidence->cca.quote_len, fp);

	fclose(fp);

	int ret = system("cca-workload-attestation verify -f received_ear.jwt -o result.json" );
    if(ret == 0) {
        printf("Verification succeeded, result written to result.json\n");
        // TODO： Parse result.json with policy  
        return ENCLAVE_VERIFIER_ERR_NONE;
    } else {
        printf("Verification failed with code %d\n", WEXITSTATUS(ret));
        return -1;
    }
}
