# Normal and occlum mode
set(CMAKE_C_FLAGS "${CMAKE_C_FLArGS}")
set(RATS_TLS_LDFLAGS "-fPIC -Bsymbolic -ldl")

if(CCA)
    message("Using aarch64 cross compilation for CCA mode")
endif()

if(OCCLUM)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DOCCLUM")
endif()

if(DEBUG)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -ggdb -O0")
else()
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O2")
endif()

# SGX mode
if(SGX)
    if(SGX_HW)
        set(SGX_URTS_LIB sgx_urts)
        set(SGX_USVC_LIB sgx_uae_service)
        set(SGX_TRTS_LIB sgx_trts)
        set(SGX_TSVC_LIB sgx_tservice)
    else()
        set(SGX_URTS_LIB sgx_urts_sim)
        set(SGX_USVC_LIB sgx_uae_service_sim)
        set(SGX_TRTS_LIB sgx_trts_sim)
        set(SGX_TSVC_LIB sgx_tservice_sim)
    endif()
    set(SGX_DACP_QL sgx_dcap_ql)
    set(SGX_DACP_QUOTEVERIFY sgx_dcap_quoteverify)
    set(SGX_DCAP_TVL sgx_dcap_tvl)

    set(APP_COMMON_FLAGS "-fPIC -Wno-attributes")

    if(SGX_DEBUG)
        set(SGX_COMMON_FLAGS "${SGX_COMMON_FLAGS} -O0 -g")
        set(APP_COMMON_FLAGS "${APP_COMMON_FLAGS} -DDEBUG -UNDEBUG -UEDEBUG")
    elseif(SGX_PRERELEASE)
        set(SGX_COMMON_FLAGS "${SGX_COMMON_FLAGS} -O2")
        set(APP_COMMON_FLAGS "${APP_COMMON_FLAGS} -DNDEBUG -DEDEBUG -UDEBUG")
    elseif(SGX_RELEASE)
        set(SGX_COMMON_FLAGS "${SGX_COMMON_FLAGS} -O2")
        set(APP_COMMON_FLAGS "${APP_COMMON_FLAGS} -DNDEBUG -UEDEBUG -UDEBUG")
    endif()

    set(SGX_COMMON_FLAGS "${SGX_COMMON_FLAGS} -Wall -Wextra -Winit-self")
    set(SGX_COMMON_FLAGS "${SGX_COMMON_FLAGS} -Wpointer-arith -Wreturn-type -Waddress -Wsequence-point")
    set(SGX_COMMON_FLAGS "${SGX_COMMON_FLAGS} -Wformat -Wformat-security -Wmissing-include-dirs -Wfloat-equal")
    set(SGX_COMMON_FLAGS "${SGX_COMMON_FLAGS} -Wundef -Wshadow -Wcast-align")
    set(SGX_COMMON_FLAGS "${SGX_COMMON_FLAGS} -Wredundant-decls")

    set(ENCLAVE_COMMON_FLAGS "-m64 -Wall -nostdinc -ffreestanding -fvisibility=hidden -fpic -fpie -ffunction-sections -fdata-sections")

    if(CMAKE_C_COMPILER_VERSION VERSION_LESS 4.9)
        set(ENCLAVE_COMMON_FLAGS "${ENCLAVE_COMMON_FLAGS} -fstack-protector")
    else()
        set(ENCLAVE_COMMON_FLAGS "${ENCLAVE_COMMON_FLAGS} -fstack-protector-strong")
    endif()

    set(SGX_COMMON_CFLAGS "${SGX_COMMON_FLAGS} -Wstrict-prototypes -Wunsuffixed-float-constants -Wno-implicit-function-declaration -std=c11")
    set(SGX_COMMON_CXXFLAGS "${SGX_COMMON_FLAGS} -Wnon-virtual-dtor -std=c++11")

    set(ENCLAVE_INCLUDES "${SGX_INCLUDE}" "${SGX_TLIBC_INCLUDE}" "${SGX_LIBCXX_INCLUDE}" "/usr/include")
    set(ENCLAVE_C_FLAGS "${CMAKE_C_FLAGS} ${SGX_COMMON_CFLAGS} ${ENCLAVE_COMMON_FLAGS}")
    set(ENCLAVE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${SGX_COMMON_CXXFLAGS} ${ENCLAVE_COMMON_FLAGS} -nostdinc++")

    set(APP_INCLUDES "${SGX_INCLUDE}")
    set(APP_C_FLAGS "${CMAKE_C_FLAGS} ${SGX_COMMON_CFLAGS} ${APP_COMMON_FLAGS}")
    set(APP_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${SGX_COMMON_CXXFLAGS} ${APP_COMMON_FLAGS}")
endif()
