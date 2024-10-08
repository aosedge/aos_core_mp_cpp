/*
 * Copyright (C) 2024 Renesas Electronics Corporation.
 * Copyright (C) 2024 EPAM Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef CMCONNECTION_HPP_
#define CMCONNECTION_HPP_

#include <atomic>
#include <functional>
#include <future>
#include <memory>
#include <optional>
#include <thread>
#include <vector>

#include <Poco/Runnable.h>
#include <Poco/TaskManager.h>
#include <Poco/UUID.h>
#include <Poco/UUIDGenerator.h>

#include <aos/common/tools/error.hpp>

#include "config/config.hpp"
#include "downloader/downloader.hpp"
#include "filechunker/filechunker.hpp"
#include "imageunpacker/imageunpacker.hpp"
#include "types.hpp"

namespace aos::mp::communication {

/**
 * CM connection class.
 */
class CMConnection {
public:
    /**
     * Constructor.
     */
    CMConnection();

    /**
     * Initializes connection.
     *
     * @param cfg Configuration.
     * @param certProvider Certificate provider.
     * @param comManager Communication manager.
     * @param channel Channel.
     * @return Error.
     */
    Error Init(const config::Config& cfg, HandlerItf& handler, CommunicationManagerItf& comManager,
        iamclient::CertProviderItf* certProvider = nullptr);

    /**
     * Closes connection.
     */
    void Close();

private:
    static constexpr auto cConnectionTimeout = std::chrono::seconds(3);

    class Task : public Poco::Task {
    public:
        using Callback = std::function<void()>;

        Task(Callback callback)
            : Poco::Task(generateTaskName())
            , mCallback(std::move(callback))
        {
        }

        void runTask() override { mCallback(); }

    private:
        static std::string generateTaskName()
        {
            static Poco::UUIDGenerator mUuidGenerator;

            return mUuidGenerator.create().toString();
        }

        Callback mCallback;
    };

    std::future<void> StartTaskWithWait(std::function<void()> func)
    {
        auto              promise = std::make_shared<std::promise<void>>();
        std::future<void> future  = promise->get_future();

        auto task = new Task([func, promise]() {
            func();
            promise->set_value();
        });

        mTaskManager.start(task);

        return future;
    }

    void StartTask(std::function<void()> func) { mTaskManager.start(new Task(std::move(func))); }

    void RunSecureChannel();
    void RunOpenChannel();
    void ReadSecureMsgHandler();
    void ReadOpenMsgHandler();
    void WriteSecureMsgHandler();

    bool  IsPublicMessage(const std::vector<uint8_t>& message);
    Error SendSMClockSync();

    Error Download(const std::string& url, uint64_t requestID, const std::string& contentType);
    Error SendFailedImageContentResponse(uint64_t requestID, const Error& err);
    Error SendImageContentInfo(const filechunker::ContentInfo& contentInfo);
    RetWithError<filechunker::ContentInfo> GetFileContent(
        const std::string& url, uint64_t requestID, const std::string& contentType);

    Error SendMessage(std::vector<uint8_t> message, std::shared_ptr<CommChannelItf>& channel);
    RetWithError<std::vector<uint8_t>> ReadMessage(std::shared_ptr<CommChannelItf>& channel);

    std::shared_ptr<CommChannelItf> mCMCommOpenChannel;
    std::shared_ptr<CommChannelItf> mCMCommSecureChannel;
    HandlerItf*                     mHandler {};

    Poco::TaskManager mTaskManager;

    std::optional<downloader::Downloader>       mDownloader;
    std::optional<imageunpacker::ImageUnpacker> mImageUnpacker;

    std::atomic<bool>       mShutdown {};
    std::mutex              mMutex;
    std::condition_variable mCondVar;
};

} // namespace aos::mp::communication

#endif /* CMCONNECTION_HPP_ */
