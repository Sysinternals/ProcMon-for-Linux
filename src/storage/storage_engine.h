/*
    Procmon-for-Linux

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#ifndef STORAGE_ENGINE_H
#define STORAGE_ENGINE_H

#include <vector>
#include <tuple>
#include <map>

#include "../common/telemetry.h"
#include "../common/event.h"
#include "../display/screen_configuration.h"

class IStorageEngine
{
protected:
    std::map<std::string, std::tuple<int, uint64_t>> _syscallHitMap;

public:
    IStorageEngine() {}
    virtual ~IStorageEngine(){};

    // Initialize the storage engine with expected syscalls to be stored.
    virtual bool Initialize(const std::vector<Event> &syscalls) = 0;

    // Query API

    // Get all telemetry data for given pid
    // optionally filter by syscalls.
    virtual std::vector<ITelemetry> QueryByPid(pid_t pid, const std::vector<Event> &syscalls = {}) = 0;

    // Get all telemetry data for a given pid in a timespan
    // optionally filter by syscalls.
    // notes: - specify only start_time to get everything _after_
    //        - specify only end_time to get everything _before_
    virtual std::vector<ITelemetry> QueryByPidInTimespan(
        pid_t pid, double start_time = 0.0, double end_time = 0.0, const std::vector<Event> &syscalls = {}) = 0;

    // Get all telemetry data for given pids
    // optionally filter by syscalls.
    virtual std::vector<ITelemetry> QueryByPids(std::vector<pid_t> pids, const std::vector<Event> &syscalls = {}) = 0;

    // Get all telemetry data for a given pids in a timespan
    // optionally filter by syscalls.
    // notes: - specify only start_time to get everything _after_
    //        - specify only end_time to get everything _before_
    virtual std::vector<ITelemetry> QueryByPidsInTimespan(
        std::vector<pid_t> pids, double start_time = 0.0, double end_time = 0.0, const std::vector<Event> &syscalls = {}) = 0;

    // Get a specified page of telemetry data for a given pids
    // optionally filter by syscalls.
    virtual std::vector<ITelemetry> QueryByEventsinPage(
        std::vector<pid_t> pids, uint pageNumber, uint eventsPerPage, ScreenConfiguration::sort orderBy, bool asc, const std::vector<Event>& syscalls = {}) = 0;

    virtual std::vector<ITelemetry> QueryByResultCodeInTimespan(
        int resultCode, double start_time = 0.0, double end_time = 0.0, const std::vector<Event> &syscalls = {}) = 0;

    virtual std::vector<ITelemetry> QueryByFilteredEventsinPage(
        std::string filter, std::vector<pid_t> pids, uint pageNumber, uint eventsPerPage, ScreenConfiguration::sort orderBy, bool asc, const std::vector<Event>& syscalls = {}) = 0;

    virtual std::vector<int> QueryIdsBySearch(
        std::string search, std::vector<pid_t> pids, ScreenConfiguration::sort orderBy, bool asc, const std::vector<Event>& syscalls = {}) = 0;

    // Store API
    virtual bool Store(ITelemetry data) = 0;
    virtual bool StoreMany(std::vector<ITelemetry> data) = 0;
    virtual int Size() { return 0; };
    virtual bool Export(std::tuple<uint64_t, std::string> startTime, std::string filePath) { return false; };
    virtual bool Clear() { return false; };

    // Load API
    virtual std::tuple<uint64_t, std::string> Load(std::string filePath) = 0;

    // Hitmap API
    virtual std::map<std::string, std::tuple<int, uint64_t>> GetHitmap () { return _syscallHitMap; }
};

#endif