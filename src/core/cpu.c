/* Copyright (c) 2021 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "internal/cpu.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
// clang-format off
#ifndef SGX
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <fcntl.h>
#include <unistd.h>
#include <rats-tls/log.h>
#else
#include "rtls_t.h"
#endif
// clang-format on

#ifndef SGX
// clang-format off
static inline void cpuid(int *eax, int *ebx, int *ecx, int *edx)
{
#if defined(__x86_64__)
	asm volatile("cpuid"
		     : "=a"(*eax), "=b"(*ebx), "=c"(*ecx), "=d"(*edx)
		     : "0"(*eax), "1"(*ebx), "2"(*ecx), "3"(*edx)
		     : "memory");
#elif defined(__aarch64__)
	// ARM64 平台上不支持直接的CPUID指令
	*eax = *ebx = *ecx = *edx = 0;
#else
	/* on 32bit, ebx can NOT be used as PIC code */
	asm volatile("xchgl %%ebx, %1; cpuid; xchgl %%ebx, %1"
		     : "=a"(*eax), "=r"(*ebx), "=c"(*ecx), "=d"(*edx)
		     : "0"(*eax), "1"(*ebx), "2"(*ecx), "3"(*edx)
		     : "memory");
#endif
}
// clang-format on

static inline void __cpuidex(int a[4], int b, int c) {
  a[0] = b;
  a[2] = c;
  cpuid(&a[0], &a[1], &a[2], &a[3]);
}

static bool is_sgx_device(const char *dev) {
  struct stat st;

  if (stat(dev, &st))
    return false;

  return (st.st_mode & S_IFCHR) && (major(st.st_rdev) == SGX_DEVICE_MAJOR_NUM);
}

static bool is_legacy_oot_kernel_driver(void) {
  return is_sgx_device("/dev/isgx");
}

/* Prior to DCAP 1.10 release, the DCAP OOT driver uses this legacy
 * name.
 */
static bool is_dcap_1_9_oot_kernel_driver(void) {
  return is_sgx_device("/dev/sgx/enclave");
}

/* Since DCAP 1.10 release, the DCAP OOT driver uses the same name
 * as in-tree driver.
 */
static bool is_in_tree_kernel_driver(void) {
  return is_sgx_device("/dev/sgx_enclave");
}
#else
static inline void __cpuidex(int a[4], int b, int c) {
  a[0] = b;
  a[2] = c;
  ocall_cpuid(&a[0], &a[1], &a[2], &a[3]);
}

static bool is_legacy_oot_kernel_driver(void) {
  bool retval;

  ocall_is_sgx_dev(&retval, "/dev/isgx");

  return retval;
}

/* Prior to DCAP 1.10 release, the DCAP OOT driver uses this legacy
 * name.
 */
static bool is_dcap_1_9_oot_kernel_driver(void) {
  bool retval;

  ocall_is_sgx_dev(&retval, "/dev/sgx/enclave");

  return retval;
}

/* Since DCAP 1.10 release, the DCAP OOT driver uses the same name
 * as in-tree driver.
 */
static bool is_in_tree_kernel_driver(void) {
  bool retval;

  ocall_is_sgx_dev(&retval, "/dev/sgx_enclave");

  return retval;
}
#endif

/* return true means in sgx1 enabled */
static bool __is_sgx1_supported(void) {
  int cpu_info[4] = {0, 0, 0, 0};

  __cpuidex(cpu_info, SGX_CPUID, 0);

  return !!(cpu_info[0] & SGX1_STRING);
}

static bool __is_sgx2_supported(void) {
  int cpu_info[4] = {0, 0, 0, 0};

  __cpuidex(cpu_info, SGX_CPUID, 0);

  return !!(cpu_info[0] & SGX2_STRING);
}

bool is_sgx1_supported(void) {
  if (!__is_sgx1_supported())
    return false;

  /* SGX2 using ECDSA attestation is not compatible with SGX1
   * which uses EPID attestation.
   */
  if (is_sgx2_supported())
    return false;

  /* Check whether the kernel driver is accessible */
  if (!is_legacy_oot_kernel_driver())
    return false;

  return true;
}

bool is_sgx2_supported(void) {
  if (!__is_sgx2_supported())
    return false;

  /* Check whether the kernel driver is accessible */
  if (!is_dcap_1_9_oot_kernel_driver() && !is_in_tree_kernel_driver())
    return false;

  return true;
}

/* return true means in td guest */
bool is_tdguest_supported(void) {
  uint32_t sig[4] = {0, 0, 0, 0};

  __cpuidex(sig, TDX_CPUID, 0);

  /* "IntelTDX    " */
  return (sig[1] == 0x65746e49) && (sig[3] == 0x5844546c) &&
         (sig[2] == 0x20202020);
}

#ifndef SGX
/* rdmsr 0xc0010131
 * bit[0]
 * 	0 = Guest SEV is not active;
 * 	1 = Guest SEV is active
 * bit[1]
 * 	0 = Guest SEV-ES is not active
 * 	1 = Guest SEV-ES is active
 * bit[2]
 * 	0 = Guest SEV-SNP is not active;
 * 	1 = Guest SEV-SNP is active
 */
static uint64_t read_msr(uint32_t reg) {
  int fd = open("/dev/cpu/0/msr", O_RDONLY);

  if (fd < 0) {
    RTLS_ERR("failed to open msr\n");
    return 0;
  }

  uint64_t data;
  if (pread(fd, &data, sizeof(data), reg) != sizeof(data)) {
    close(fd);
    RTLS_ERR("failed to read msr %#x\n", reg);
    return 0;
  }

  close(fd);

  return data;
}
#endif

static bool is_amd_cpu(void) {
  int cpu_info[4] = {0, 0, 0, 0};

  __cpuidex(cpu_info, 0, 0);

  /* The twelve 8-bit ASCII character codes that form the
   * string "AuthenticAMD".
   */
  return (cpu_info[1] == 0x68747541 && cpu_info[2] == 0x444d4163 &&
          cpu_info[3] == 0x69746e65);
}

static bool is_hygon_cpu(void) {
  int cpu_info[4] = {0, 0, 0, 0};

  __cpuidex(cpu_info, 0, 0);

  /* The twelve 8-bit ASCII character codes that form the
   * string "HygonGenuine".
   */
  return (cpu_info[1] == 0x6f677948 && cpu_info[2] == 0x656e6975 &&
          cpu_info[3] == 0x6e65476e);
}

/* check whether running in AMD SEV-SNP guest */
bool is_snpguest_supported(void) {
#ifndef SGX
  if (!is_amd_cpu())
    return false;

  return !!(read_msr(SEV_STATUS_MSR) & (1 << SEV_SNP_FLAG));
#else
  return false;
#endif
}

/* check whether running in AMD SEV(-ES) guest */
bool is_sevguest_supported(void) {
#ifndef SGX
  if (!is_amd_cpu())
    return false;

  uint64_t data = read_msr(SEV_STATUS_MSR);
  return !!data || !!(data & (1 << SEV_ES_FLAG));
#else
  return false;
#endif
}

/* check whether running in HYGON CSV guest */
bool is_csvguest_supported(void) {
#ifndef SGX
  if (!is_hygon_cpu())
    return false;

  uint64_t data = read_msr(SEV_STATUS_MSR);
  return !!(data & ((1 << SEV_FLAG) | (1 << SEV_ES_FLAG)));
#else
  return false;
#endif
}

bool is_ccaguest_supported(void) {
  // todo
  return true;
}
