/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _ENCLAVE_CERT_H
#define _ENCLAVE_CERT_H

typedef struct {
	const unsigned char *organization;
	const unsigned char *organization_unit;
	const unsigned char *common_name;
} cert_subject_t;

typedef struct {
	uint8_t ias_report[2 * 1024];
	uint32_t ias_report_len;
	uint8_t ias_sign_ca_cert[2 * 1024];
	uint32_t ias_sign_ca_cert_len;
	uint8_t ias_sign_cert[2 * 1024];
	uint32_t ias_sign_cert_len;
	uint8_t ias_report_signature[2 * 1024];
	uint32_t ias_report_signature_len;
} attestation_verification_report_t;

typedef struct {
	uint8_t quote[8192];
	uint32_t quote_len;
} ecdsa_attestation_evidence_t;

typedef struct {
	uint8_t report[8192];
	uint32_t report_len;
} la_attestation_evidence_t;

typedef struct {
	uint8_t quote[8192];
	uint32_t quote_len;
} tdx_attestation_evidence_t;

typedef struct {
	uint8_t report[8192];
	uint32_t report_len;
} snp_attestation_evidence_t;

typedef struct {
	uint8_t report[8192];
	uint32_t report_len;
} sev_attestation_evidence_t;

typedef struct {
	uint8_t report[8192];
	uint32_t report_len;
} csv_attestation_evidence_t;

typedef struct {
	uint8_t quote[8192];
	uint32_t quote_len;
} cca_attestation_evidence_t;

typedef struct {
	char type[ENCLAVE_ATTESTER_TYPE_NAME_SIZE];
	union {
		attestation_verification_report_t epid;
		ecdsa_attestation_evidence_t ecdsa;
		la_attestation_evidence_t la;
		tdx_attestation_evidence_t tdx;
		snp_attestation_evidence_t snp;
		sev_attestation_evidence_t sev;
		csv_attestation_evidence_t csv;
		cca_attestation_evidence_t cca;
	};
} attestation_evidence_t;

typedef struct {
	cert_subject_t subject;
	unsigned int cert_len;
	uint8_t *cert_buf;
	uint8_t *evidence_buffer;
	size_t evidence_buffer_size;
	uint8_t *endorsements_buffer;
	size_t endorsements_buffer_size;
} rats_tls_cert_info_t;

#endif
