#
# Copyright (C) 2024 EPAM Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

set(TARGET downloader)

# ######################################################################################################################
# Compiler flags
# ######################################################################################################################

add_definitions(-DLOG_MODULE="downloader")

# ######################################################################################################################
# Sources
# ######################################################################################################################

set(SOURCES downloader.cpp)

# ######################################################################################################################
# Includes
# ######################################################################################################################

# ######################################################################################################################
# Target
# ######################################################################################################################

add_library(${TARGET} STATIC ${SOURCES})

# ######################################################################################################################
# Libraries
# ######################################################################################################################

target_link_libraries(${TARGET} PUBLIC aosutils aoscommon CURL::libcurl Poco::Foundation)
