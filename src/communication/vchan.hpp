/*
 * Copyright (C) 2024 Renesas Electronics Corporation.
 * Copyright (C) 2024 EPAM Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef VCHAN_HPP_
#define VCHAN_HPP_

extern "C" {
#include <libxenvchan.h>
}

#include <atomic>

#include "config/config.hpp"
#include "types.hpp"

namespace aos::mp::communication {

/**
 * Virtual Channel class.
 */
class VChan : public TransportItf {
public:
    /**
     * Initializes the virtual channel.
     *
     * @param config Configuration
     * @return Error
     */
    Error Init(const VChanConfig& config);

    /**
     * Connects to the virtual channel.
     */
    Error Connect() override;

    /**
     * Reads message from the virtual channel.
     *
     * @param message Message
     * @return aos::Error
     */
    Error Read(std::vector<uint8_t>& message) override;

    /**
     * Writes message to the virtual channel.
     *
     * @param message Message
     * @return aos::Error
     */
    Error Write(std::vector<uint8_t> message) override;

    /**
     * Closes the virtual channel.
     *
     * @return aos::Error
     */
    Error Close() override;

private:
    Error ConnectToVChan(struct libxenvchan*& vchan, const std::string& path, int domain);

    struct libxenvchan* mVChanRead {};
    struct libxenvchan* mVChanWrite {};
    VChanConfig         mConfig;
    std::atomic<bool>   mShutdown {false};
};

} // namespace aos::mp::communication

#endif // VCHAN_HPP_
