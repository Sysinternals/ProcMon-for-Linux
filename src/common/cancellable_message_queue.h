// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <optional>
#include <mutex>
#include <queue>


/// A single-reader, single-writer, single-ended queue
/// capable of being cancelled externally
/// for getting out of a blocking wait.
template<typename T>
class CancellableMessageQueue
{
  private:
    std::mutex              writeLock;
    std::mutex              readLock;
    std::condition_variable readCondition;
    std::atomic<bool> cancelled = false;

    std::queue<T> leftQueue;
    std::queue<T> rightQueue;

    std::queue<T> *currentWriteQueue = &leftQueue;
    std::queue<T> *currentReadQueue = &rightQueue;

    void swapQueues()
    {
        std::unique_lock<std::mutex> lock(writeLock);
        std::swap(currentReadQueue, currentWriteQueue);
    };

  public:
    CancellableMessageQueue() {};
    ~CancellableMessageQueue() {};

    std::optional<T> pop()
    {
        std::unique_lock<std::mutex> lock(readLock);
        readCondition.wait(lock, [&]{
            return !currentReadQueue->empty() ||
            !currentWriteQueue->empty() ||
            cancelled;
        });
        // currently own the lock

        // if we're cancelled, return an empty optional
        if (cancelled) return std::nullopt;

        // otherwise, determine which queue to read from
        if (currentReadQueue->empty() && !currentWriteQueue->empty())
        {
            // swap the queues!
            swapQueues();
        }

        T retVal = currentReadQueue->front();
        currentReadQueue->pop();
        return retVal;
    };

    void push(T value)
    {
        std::unique_lock<std::mutex> lock(writeLock);
        // got lock!
        currentWriteQueue->push(value);
        readCondition.notify_all();
    };

    void push(std::vector<T> values)
    {
        std::unique_lock<std::mutex> lock(writeLock);
        // got lock!
        for (auto& el : values)
        {
            currentWriteQueue->push(std::move(el));
        }
        readCondition.notify_all();
    }

    const bool isCancelled() const { return cancelled; };

    void cancel()
    {
        cancelled = true;
        readCondition.notify_all();
    };
};