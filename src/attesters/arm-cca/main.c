/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <rats-tls/attester.h>
#include <rats-tls/log.h>

extern enclave_attester_err_t enclave_attester_register(enclave_attester_opts_t *);
extern enclave_attester_err_t arm_cca_attester_pre_init(void);
extern enclave_attester_err_t arm_cca_attester_init(enclave_attester_ctx_t *,
						   rats_tls_cert_algo_t algo);
extern enclave_attester_err_t arm_cca_collect_evidence(enclave_attester_ctx_t *,
						      attestation_evidence_t *,
						      rats_tls_cert_algo_t algo, uint8_t *,
						      uint32_t hash_len);
extern enclave_attester_err_t arm_cca_attester_cleanup(enclave_attester_ctx_t *);

static enclave_attester_opts_t arm_cca_attester_opts = {
	.api_version = ENCLAVE_ATTESTER_API_VERSION_DEFAULT,
	.flags = ENCLAVE_ATTESTER_OPTS_FLAGS_CCA_GUEST,
	.name = "arm_cca",
	.priority = 99,
	.pre_init = arm_cca_attester_pre_init,
	.init = arm_cca_attester_init,
	.collect_evidence = arm_cca_collect_evidence,
	.cleanup = arm_cca_attester_cleanup,
};


void __attribute__((constructor)) libattester_arm_cca_init(void)
{
	RTLS_DEBUG("ARM CCA libattester init called\n");

	enclave_attester_err_t err = enclave_attester_register(&arm_cca_attester_opts);
	if (err != ENCLAVE_ATTESTER_ERR_NONE)
		RTLS_ERR("failed to register the enclave attester 'arm-cca' %#x\n", err);
}
