/*
    Procmon-for-Linux

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#ifndef MOCK_STORAGE_ENGINE_H
#define MOCK_STORAGE_ENGINE_H

#include <map>
#include <mutex>
#include <string>
#include <vector>

#include "storage_engine.h"
#include "../common/telemetry.h"
#include "../common/event.h"
#include "../display/screen_configuration.h"

typedef  ITelemetry MockTelemetry;

class MockStorageEngine : public IStorageEngine
{
private:
    std::mutex _mapLock;
    std::map<pid_t, std::vector<MockTelemetry>> _dataStore;
public:
    bool Initialize(const std::vector<Event>& syscalls) override {return true;};

    std::vector<MockTelemetry> QueryByPid(pid_t pid, const std::vector<Event>& syscalls = {}) override;

    virtual std::vector<MockTelemetry> QueryByPidInTimespan(
        pid_t pid, double start_time = 0.0, double end_time = 0.0, const std::vector<Event>& syscalls = {}) override {return std::vector<MockTelemetry>();};

    virtual std::vector<MockTelemetry> QueryByPids(std::vector<pid_t> pids, const std::vector<Event>& syscalls = {}) override {return std::vector<MockTelemetry>();};

    virtual std::vector<MockTelemetry> QueryByPidsInTimespan(
        std::vector<pid_t> pids, double start_time = 0.0, double end_time = 0.0, const std::vector<Event>& syscalls = {}) override {return std::vector<MockTelemetry>();};

    virtual std::vector<ITelemetry> QueryByEventsinPage(
        std::vector<pid_t> pids, uint pageNumber, uint eventsPerPage, ScreenConfiguration::sort orderBy, bool asc, const std::vector<Event>& syscalls = {}) override {return std::vector<ITelemetry>();};

    virtual std::vector<ITelemetry> QueryByResultCodeInTimespan(
        int resultCode, double start_time = 0.0, double end_time = 0.0, const std::vector<Event> &syscalls = {}) override {return std::vector<ITelemetry>();};

    virtual std::vector<ITelemetry> QueryByFilteredEventsinPage(
        std::string filter, std::vector<pid_t> pids, uint pageNumber, uint eventsPerPage, ScreenConfiguration::sort orderBy, bool asc, const std::vector<Event>& syscalls = {}) override {return std::vector<ITelemetry>();};

    virtual std::vector<int> QueryIdsBySearch(
        std::string search, std::vector<pid_t> pids, ScreenConfiguration::sort orderBy, bool asc, const std::vector<Event>& syscalls = {}) override;

    // Store API
    bool Store(MockTelemetry data) override;
    bool StoreMany(std::vector<MockTelemetry> data) override;
    int Size() override { return 0; };

    // Load API
    std::tuple<uint64_t, std::string> Load(std::string filepath) { return std::make_tuple(0, ""); };
};

#endif // MOCK_STORAGE_ENGINE_H