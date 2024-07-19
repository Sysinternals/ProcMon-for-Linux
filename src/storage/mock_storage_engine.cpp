/*
    Procmon-for-Linux

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

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