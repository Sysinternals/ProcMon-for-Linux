// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "mock_storage_engine.h"


std::vector<MockTelemetry> MockStorageEngine::QueryByPid(pid_t pid, const std::vector<Event>& syscalls)
{
    std::lock_guard<std::mutex> guard(_mapLock);
    auto search = _dataStore.find(pid);
    return (search != _dataStore.end()) ? search->second : std::vector<MockTelemetry> {};
}

bool MockStorageEngine::Store(MockTelemetry data)
{
    std::lock_guard<std::mutex> guard(_mapLock);
    _dataStore[data.pid].push_back(data);
    return true;
}

bool MockStorageEngine::StoreMany(std::vector<MockTelemetry> data)
{
    for (auto& datum : data)
    {
        Store(datum);
    }
    return true;
}

std::vector<int> MockStorageEngine::QueryIdsBySearch(
    std::string search, std::vector<pid_t> pids, ScreenConfiguration::sort orderBy, bool asc, const std::vector<Event>& syscalls)
{
    return std::vector<int>();
}