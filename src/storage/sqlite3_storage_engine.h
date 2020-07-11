// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#pragma once

#include <map>
#include <sqlite3.h>
#include <string>
#include <vector>

#include "storage_engine.h"
#include "../common/telemetry.h"
#include "../display/screen_configuration.h"

class Sqlite3StorageEngine : public IStorageEngine
{
private:
    bool ready;

    // Since we are only expecting only one writer to access the storage engine at a time,
    // this is okay for now. However once more writers are introduced, telemetryCount should 
    // declared as an atomic. 
    uint telemetryCount;

    std::vector<Event> syscallList;

    sqlite3* dbConnection;
    
    std::string addPidFilterToSQLQuery(const std::string initialQuery, std::vector<pid_t> pids, const bool first);

    std::string addSyscallFilterToSQLQuery(const std::string initialQuery, std::vector<Event> events, const bool first);

    void prepareAndGetFromSqlite3(const std::string raw_sql_statement, std::vector<ITelemetry>& results);
    void prepareAndGetIdsFromSqlite3(const std::string raw_sql_statement, std::vector<int>& results);

    ITelemetry parseSqlite3Row(sqlite3_stmt *preppedSqlStmt);

    std::vector<ITelemetry> getFromSqlite3(sqlite3_stmt* preppedSqlStmt);
    std::vector<int> getIdsFromSqlite3(sqlite3_stmt* preppedSqlStmt);

public:
    Sqlite3StorageEngine(): ready(false) {};
    ~Sqlite3StorageEngine();
    
    bool Initialize(const std::vector<Event>& syscalls) override;

    // Query API

    std::vector<ITelemetry> QueryByPid(pid_t pid, const std::vector<Event>& syscalls = {}) override;

    std::vector<ITelemetry> QueryByPids(std::vector<pid_t> pids, const std::vector<Event>& syscalls = {}) override;

    std::vector<ITelemetry> QueryByPidInTimespan(
        pid_t pid, double start_time = 0.0, double end_time = 0.0, const std::vector<Event>& syscalls = {}) override;

    std::vector<ITelemetry> QueryByPidsInTimespan(
        std::vector<pid_t> pids, double start_time = 0.0, double end_time = 0.0, const std::vector<Event>& syscalls = {}) override;

    std::vector<ITelemetry> QueryByResultCodeInTimespan(
        int resultCode, double start_time = 0.0, double end_time = 0.0, const std::vector<Event>& syscalls = {}) override;

    std::vector<ITelemetry> QueryByEventsinPage(
        std::vector<pid_t> pids, uint pageNumber, uint eventsPerPage, ScreenConfiguration::sort orderBy, bool asc, const std::vector<Event>& syscalls = {}) override;

    std::vector<ITelemetry> QueryByFilteredEventsinPage(
        std::string filter, std::vector<pid_t> pids, uint pageNumber, uint eventsPerPage, ScreenConfiguration::sort orderBy, bool asc, const std::vector<Event>& syscalls = {}) override;

    std::vector<int> QueryIdsBySearch(
        std::string search, std::vector<pid_t> pids, ScreenConfiguration::sort orderBy, bool asc, const std::vector<Event>& syscalls = {}) override;

    // Store API
    bool Store(ITelemetry data) override;
    bool StoreMany(std::vector<ITelemetry> data) override;
    bool Clear() override;

    // Load API
    std::tuple<uint64_t, std::string> Load(std::string filePath) override;

    // Debug API
    int Size() override;
    bool Export(std::tuple<uint64_t, std::string> startTime, std::string filePath) override;
};