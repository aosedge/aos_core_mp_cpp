#
# Copyright (C) 2024 Renesas Electronics Corporation.
# Copyright (C) 2024 EPAM Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

cmake_minimum_required(VERSION 3.19)

project("aos_messageproxy")

# ######################################################################################################################
# Options
# ######################################################################################################################

option(WITH_TEST "build with test" OFF)
option(WITH_COVERAGE "build with coverage" OFF)
option(WITH_DOC "build with documenation" OFF)
option(WITH_VCHAN "build with vchan" ON)

message(STATUS)
message(STATUS "${CMAKE_PROJECT_NAME} configuration:")
message(STATUS "CMAKE_BUILD_TYPE              = ${CMAKE_BUILD_TYPE}")
message(STATUS "CMAKE_INSTALL_PREFIX          = ${CMAKE_INSTALL_PREFIX}")
message(STATUS)
message(STATUS "WITH_VCHAN                    = ${WITH_VCHAN}")
message(STATUS)
message(STATUS "WITH_TEST                     = ${WITH_TEST}")
message(STATUS "WITH_COVERAGE                 = ${WITH_COVERAGE}")
message(STATUS "WITH_DOC                      = ${WITH_DOC}")
message(STATUS)

# ######################################################################################################################
# External project options
# ######################################################################################################################

# aos core api options
set(WITH_SM_API ON)
set(WITH_IAM_API ON)
set(WITH_AOS_PROTOCOL ON)

# ######################################################################################################################
# Compiler flags
# ######################################################################################################################

set(common_flags "-fPIC -Wall -Werror -Wextra -Wpedantic")

set(CMAKE_CXX_FLAGS "${common_flags} ${CMAKE_CXX_FLAGS}")
set(CMAKE_C_FLAGS "${common_flags} ${CMAKE_C_FLAGS}")
set(CMAKE_CXX_STANDARD 17)

if(WITH_VCHAN)
    add_definitions(-DVCHAN)
endif()

set(AOS_CORE_LIB_DIR ${CMAKE_CURRENT_SOURCE_DIR}/external/aos_core_common_cpp/external/aos_core_lib_cpp)
set(AOS_CORE_COMMON_LIB_DIR ${CMAKE_CURRENT_SOURCE_DIR}/external/aos_core_common_cpp)

if(WITH_TEST)
    add_definitions(-include ${AOS_CORE_LIB_DIR}/include/aos/test/aoscoretestconfig.hpp)
endif()

# ######################################################################################################################
# Versioning
# ######################################################################################################################

find_package(Git)

if(NOT GIT_FOUND)
    set(GIT_EXECUTABLE git)
endif()

execute_process(
    OUTPUT_FILE ${CMAKE_BINARY_DIR}/version.hpp
    COMMAND
        ${CMAKE_COMMAND} -D GIT_EXECUTABLE=${GIT_EXECUTABLE} -D INPUT_FILE=${CMAKE_SOURCE_DIR}/src/version.hpp.in -D
        OUTPUT_FILE=${CMAKE_BINARY_DIR}/version.hpp -D GIT_SOURCE_DIR=${CMAKE_SOURCE_DIR} -P
        ${CMAKE_SOURCE_DIR}/cmake/GenerateVersion.cmake
)

include_directories(${CMAKE_BINARY_DIR})

# ######################################################################################################################
# Dependencies
# ######################################################################################################################

set(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake)

# Find the libcurl package
find_package(CURL REQUIRED)

# Find the libssl package
find_package(OpenSSL REQUIRED)

if(WITH_VCHAN)
    find_package(Xenvchan REQUIRED)
    if(XENVCHAN_FOUND)
        message(STATUS "Xenvchan found:")
        message(STATUS "  version: ${XENVCHAN_VERSION}")
        message(STATUS "  libraries: ${XENVCHAN_LIBRARIES}")
        message(STATUS "  include dirs: ${XENVCHAN_INCLUDE_DIRS}")
    else()
        message(FATAL_ERROR "Xenvchan not found")
    endif()
endif()

# Poco lib
find_package(Poco REQUIRED Foundation Net NetSSL Util)

if(WITH_TEST)
    find_package(GTest REQUIRED)

    include(GoogleTest)

    enable_testing()
endif()

if(WITH_COVERAGE)
    include(CodeCoverage)

    append_coverage_compiler_flags()

    set(COVERAGE_EXCLUDES "build/*" "/usr/*" "tests/*" "external/*")

    setup_target_for_coverage_lcov(
        NAME
        coverage
        EXECUTABLE
        ctest
        LCOV_ARGS
        --ignore-errors
        mismatch,negative
    )
endif()

# ######################################################################################################################
# Targets
# ######################################################################################################################

add_subdirectory(external/aos_core_common_cpp/external/aos_core_lib_cpp/src/common)
add_subdirectory(external/aos_core_common_cpp/external/aos_core_lib_cpp/src/iam)
add_subdirectory(external/aos_core_common_cpp/external/aos_core_api)
add_subdirectory(external/aos_core_common_cpp/src)
add_subdirectory(src)

if(WITH_TEST)
    add_subdirectory(external/aos_core_common_cpp/external/aos_core_lib_cpp/tests/utils)
    add_subdirectory(tests)
endif()

# ######################################################################################################################
# Doc
# ######################################################################################################################

if(WITH_DOC)
    find_package(Doxygen)

    configure_file(${CMAKE_CURRENT_SOURCE_DIR}/doxygen.cfg ${CMAKE_CURRENT_BINARY_DIR}/doxygen.cfg @ONLY)

    add_custom_target(
        doc
        ${DOXYGEN_EXECUTABLE} ${CMAKE_CURRENT_BINARY_DIR}/doxygen.cfg
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        COMMENT "Generating API documentation with Doxygen"
        VERBATIM
    )
endif()
