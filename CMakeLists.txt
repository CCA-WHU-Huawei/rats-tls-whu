# CMake version
cmake_minimum_required(VERSION 3.15.0)

# Add cmake modules path
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

# Set compiler based on build mode - MUST BE BEFORE project()
if(RATS_TLS_BUILD_MODE STREQUAL "cca")
    #set(CMAKE_SYSTEM_NAME Linux)
    #set(CMAKE_SYSTEM_PROCESSOR aarch64)
    #set(CMAKE_C_COMPILER aarch64-unknown-linux-gnu-gcc)
    #set(CMAKE_CXX_COMPILER aarch64-unknown-linux-gnu-g++)
    message(STATUS "Using aarch64 cross compilation for CCA mode")
endif()

# Project declaration after compiler settings
project(rats-tls)

# 设置 OpenSSL 查找路径
set(OPENSSL_ROOT_DIR ${CMAKE_SYSROOT}/usr)
set(OPENSSL_INCLUDE_DIR ${CMAKE_SYSROOT}/usr/include)
set(OPENSSL_CRYPTO_LIBRARY ${CMAKE_SYSROOT}/usr/lib/libcrypto.so)
set(OPENSSL_SSL_LIBRARY ${CMAKE_SYSROOT}/usr/lib/libssl.so)

# Define build mode
set(RATS_TLS_BUILD_MODE "host"
    CACHE STRING "Select build mode for rats-tls(normal|occlum|sgx|cca)")

# Print build mode
message(STATUS "Build Mode: ${RATS_TLS_BUILD_MODE}")
message(STATUS "CMAKE_MODULE_PATH: ${CMAKE_MODULE_PATH}")

# Rest of your original configuration
set(RTLS_LIB rats_tls)
set(RTLS_SRC_PATH ${CMAKE_CURRENT_LIST_DIR})
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Software version
file(STRINGS "VERSION" RATS_TLS_VERSION)
set(VERSION ${RATS_TLS_VERSION})
string(REPLACE "." ";" VERSION_LIST ${RATS_TLS_VERSION})
list(GET VERSION_LIST 0 VERSION_MAJOR)
list(GET VERSION_LIST 1 VERSION_MINOR)
list(GET VERSION_LIST 2 VERSION_PATCH)

# Build options
option(BUILD_SAMPLES "Compile sample code along with libraries" ON)
option(SGX_HW "Run SGX on hardware, OFF for simulation" ON)
option(SGX_LVI_MITIGATION "Mitigation flag, default on" ON)
option(BUILD_FUZZ "Use lib-fuzzer to fuzz the code, default OFF" OFF)

# Default build type
set(RATS_TLS_BUILD_TYPE "debug"
    CACHE STRING "Select build type for rats-tls(debug|prerelease|release)"
)

# Print build type
message(STATUS "Build Type: ${RATS_TLS_BUILD_TYPE}")

# Build type macro
# debug: DEBUG
# prerelease: PRERELEASE
# release: RELEASE
if(RATS_TLS_BUILD_TYPE STREQUAL "debug")
    set(DEBUG 1)
elseif(RATS_TLS_BUILD_TYPE STREQUAL "prerelease")
    set(PRERELEASE 1)
elseif(RATS_TLS_BUILD_TYPE STREQUAL "release")
    set(RELEASE 1)
else()
    message(FATAL_ERROR "Invalid build type!")
endif()

# Include custom modules
include(CustomInstallDirs)
include(CompilerOptions)

if(SGX)
    include(SGXCommon)
    include(SGXSSL)
    include(LibCBOR)
endif()

# Subdirectory
add_subdirectory(src)

if(BUILD_SAMPLES)
    message(STATUS "Build Samples: on")
    add_subdirectory(samples)
endif()

if(BUILD_FUZZ)
    message(STATUS "Build Fuzz: on")
    add_subdirectory(fuzz)
endif()

# Uninstall target
if(NOT TARGET uninstall)
    configure_file(
        "${CMAKE_CURRENT_SOURCE_DIR}/cmake/CMakeUninstall.cmake.in"
        "${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake"
        IMMEDIATE @ONLY)

    add_custom_target(uninstall
        COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake)
endif()
