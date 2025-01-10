/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <rats-tls/log.h>
#include <rats-tls/verifier.h>
#include <stdio.h>

extern enclave_verifier_err_t
enclave_verifier_register(enclave_verifier_opts_t *);
extern enclave_verifier_err_t arm_cca_verifier_pre_init(void);
extern enclave_verifier_err_t arm_cca_verifier_init(enclave_verifier_ctx_t *,
                                                    rats_tls_cert_algo_t algo);
extern enclave_verifier_err_t
arm_cca_verify_evidence(enclave_verifier_ctx_t *, attestation_evidence_t *,
                        uint8_t *, unsigned int hash_len,
                        attestation_endorsement_t *endorsements);
extern enclave_verifier_err_t
arm_cca_verifier_cleanup(enclave_verifier_ctx_t *);

static enclave_verifier_opts_t arm_cca_verifier_opts = {
    .api_version = ENCLAVE_VERIFIER_API_VERSION_DEFAULT,
    .flags = ENCLAVE_VERIFIER_OPTS_FLAGS_CCA,
    .name = "arm_cca",
    .priority = 99,
    .pre_init = arm_cca_verifier_pre_init,
    .init = arm_cca_verifier_init,
    .verify_evidence = arm_cca_verify_evidence,
    .cleanup = arm_cca_verifier_cleanup,
};

void __attribute__((constructor)) libverifier_arm_cca_init(void) {
  RTLS_DEBUG("called\n");

  enclave_verifier_err_t err =
      enclave_verifier_register(&arm_cca_verifier_opts);
  if (err != ENCLAVE_VERIFIER_ERR_NONE)
    RTLS_DEBUG("failed to register the enclave verifier 'arm_cca' %#x\n", err);
}
