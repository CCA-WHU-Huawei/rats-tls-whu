/* Copyright (c) 2022 Intel Corporation
 * Copyright (c) 2020-2022 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <fcntl.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <linux/sev-guest.h>
#include <rats-tls/attester.h>
#include <rats-tls/log.h>
#include "cca_migration.h"

#define SEV_GUEST_DEVICE "/dev/sev-guest"

static int cca_get_report(const uint8_t *data, size_t data_size, cca_attestation_report_t *report){

    //TODO:fix how to get report from the Realm

    return 0;

};

enclave_attester_err_t cca_migration_collect_evidence(enclave_attester_ctx_t *ctx,
						attestation_evidence_t *evidence,
						rats_tls_cert_algo_t algo, uint8_t *hash,
						uint32_t hash_len)
{
	RTLS_DEBUG("ctx %p, evidence %p, algo %d, hash %p\n", ctx, evidence, algo, hash);

	cca_attestation_report_t report;
	memset(&report, 0, sizeof(report));

	if (cca_get_report(hash, hash_len, &report)) {
		RTLS_ERR("failed to get snp report\n");
		return -ENCLAVE_ATTESTER_ERR_INVALID;
	}

	cca_attestation_evidence_t *cca_report = &evidence->cca;
	memcpy(cca_report->report, &report, sizeof(report));
	cca_report->report_len = sizeof(report);

	snprintf(evidence->type, sizeof(evidence->type), "cca_migration");

	RTLS_DEBUG("ctx %p, evidence %p, report_len %d\n", ctx, evidence, evidence->cca.report_len);

	return ENCLAVE_ATTESTER_ERR_NONE;
}