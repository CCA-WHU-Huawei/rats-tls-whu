#ifndef _CCA_MIGRATION_H
#define _CCA_MIGRATION_H

#include <stdint.h>
#include <stdio.h>
#include <rats-tls/api.h>

typedef struct cca_tcb_info {

} __attribute__((packed)) cca_tcb_info_t;

typedef struct cca_token {

} __attribute__((packed)) cca_token_t;

typedef struct snp_attestation_report {
    
    cca_token_t        attestation_token; 
    cca_tcb_info_t     platform_info; 

} __attribute__((packed)) cca_attestation_report_t;

#endif /* _CCA_MIGRATION_H */