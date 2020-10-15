// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>

#include <ctime>
#include <functional>
#include <random>
#include <string>
#include <thread>
#include <vector>
#include <bits/stdc++.h>

#include "sqlite3_storage_engine.h"
#include "../display/screen_configuration.h"

typedef ITelemetry MockTelemetry;
typedef StackTrace MockTrace;

static std::vector<pid_t> pidRange(pid_t start, pid_t end) 
{
    std::vector<pid_t> result(end-start);
    std::generate(result.begin(), result.end(), [i = start] () mutable { return i++; });
    return result;
}

static bool telemetryMatches(ITelemetry first, ITelemetry second)
{
    return first.comm == second.comm && first.syscall == second.syscall &&
    first.pid == second.pid && first.processName == second.processName;
}

static bool checkMatches(const std::vector<MockTelemetry> results, std::map<std::string, pid_t> seenProcesses, std::vector<pid_t> seenPids, uint count)
{   
    bool allTrue = true;
    for (auto& telemetry: results)
    {
        pid_t pid = seenProcesses[telemetry.processName];
        allTrue = allTrue && (std::find(seenPids.begin(), seenPids.end(), pid) != seenPids.end());
    } 
    return allTrue && results.size() == count;
}

static void storeOneItem(Sqlite3StorageEngine& engine, pid_t rangeStart, pid_t rangeEnd, std::vector<Event> syscalls)
{
    std::default_random_engine generator;
    std::uniform_int_distribution<int> pidDistribution(rangeStart, rangeEnd-1);
    std::uniform_int_distribution<int> resultDistribution(-20, 20);
    std::uniform_int_distribution<int> syscallIndexPool(0, syscalls.size()-1);
    
    auto pidDice = std::bind(pidDistribution, generator);
    auto resultDice = std::bind(resultDistribution, generator);
    auto syscallDice = std::bind(syscallIndexPool, generator);

    MockTrace trace;
    trace.userIPs = {10, 20, 40};
    trace.userSymbols = {"testSymbol1", "testSymbol2", "testSymbol3"};

    MockTelemetry telemetry {
        .pid = pidDice(),
        .stackTrace = trace,
        .comm = "",
        .processName = "Process",
        .syscall = syscalls[syscallDice()].Name(),
        .result = resultDice(),
        .duration = 0,
        .arguments = (unsigned char *)"storeOneItem arguments",
        .timestamp = 0
    };

    auto result = engine.Store(telemetry);
    CHECK(result);
}

static std::map<std::string, pid_t> storeNItems(Sqlite3StorageEngine& engine, uint count, pid_t rangeStart, pid_t rangeEnd, int resultStart, int resultEnd, 
    const std::vector<Event> syscalls, std::map<int, uint>& resFreq, std::map<pid_t, uint>& pidFreq)
{
    std::default_random_engine generator;
    std::uniform_int_distribution<int> pidDistribution(rangeStart, rangeEnd-1);
    std::uniform_int_distribution<int> resultDistribution(resultStart, resultEnd);
    std::uniform_int_distribution<int> syscallIndexPool(0, syscalls.size()-1);
    
    auto pidDice = std::bind(pidDistribution, generator);
    auto resultDice = std::bind(resultDistribution, generator);
    auto syscallDice = std::bind(syscallIndexPool, generator);

    std::map<std::string, pid_t> seenProcesses;

    std::vector<MockTelemetry> data;

    uint index = 0;
    for (std::vector<ITelemetry>::size_type i = 0; i < count; i++) 
    {
        MockTrace trace;
        trace.userIPs = {10, 20, 40};
        trace.userSymbols = {"testSymbol1", "testSymbol2", "testSymbol3"};

        std::string name = "Process" + std::to_string(index++);
        auto pid = pidDice();
        auto res = resultDice();
        MockTelemetry telemetry {
            .pid = pid,
            .stackTrace = trace,
            .comm = "",
            .processName = name,
            .syscall = syscalls[syscallDice()].Name(),
            .result = res,
            .duration = 0,
            .arguments = (unsigned char *)"storeNitems arguments",
            .timestamp = 0
        };
        data.push_back(telemetry);
        pidFreq[pid] += 1;
        resFreq[res] += 1;
        seenProcesses[name] = pid;
    }

    auto result = engine.StoreMany(data);
    CHECK(result);

    return seenProcesses;
}

TEST_CASE("storage engine must be initialized", "[Sqlite3StorageEngine]") {
    
    Sqlite3StorageEngine engine;

    SECTION("initialization works") {
        CHECK(engine.Initialize({}));
        CHECK(engine.Size() == 0);
    }

    SECTION("operations doesn't work without initialization") {
        ITelemetry mockTelemetry;
        REQUIRE_THROWS(engine.QueryByPid(0));
        REQUIRE_THROWS(engine.QueryByPids({0}));
        CHECK_FALSE(engine.Store(mockTelemetry));
        CHECK_FALSE(engine.StoreMany({mockTelemetry}));
    }

    SECTION("storage engine can only be initialized once") {
        CHECK(engine.Initialize({}));
        CHECK_FALSE(engine.Initialize({}));
    }
}

TEST_CASE("storage engine can add items", "[Sqlite3StorageEngine]") {

    // This doesn't really matter.
    std::vector<Event> mockSyscalls;
    mockSyscalls.emplace_back("sys_write");
    mockSyscalls.emplace_back("sys_read");
    mockSyscalls.emplace_back("sys_open");
    mockSyscalls.emplace_back("sys_mmap");
    
    Sqlite3StorageEngine engine;
    CHECK(engine.Initialize(mockSyscalls));
    CHECK(engine.Size() == 0);

    std::map<int, uint> resFreq;
    std::map<pid_t, uint> pidFreq;

    SECTION("storing a single item adds a matching item") {

        storeOneItem(engine, 1000, 1010, mockSyscalls);
        CHECK(engine.Size() == 1);
        std::vector<MockTelemetry> results = engine.QueryByPids(pidRange(1000, 1010));
        CHECK(results.size() == 1);
    }
    
    SECTION("storing a multitude of items adds the expected number of matching item") {
        uint elementCount = 50;
        auto seenProcesses = storeNItems(engine, elementCount, 1000, 1010, -20, 20, mockSyscalls, resFreq, pidFreq);
        auto pids = pidRange(1000, 1010);
        auto results = engine.QueryByPids(pids);
 
        CHECK(checkMatches(results, seenProcesses, pids, elementCount));
        CHECK(engine.Size() == elementCount);

    }

    SECTION("storing a large number of items adds the expected number of matching item") {
        uint elementCount = 500000; // 500 thousands
        auto seenProcesses = storeNItems(engine, elementCount, 1000, 2000, -20, 20, mockSyscalls, resFreq, pidFreq);
        auto pids = pidRange(1000, 2000);
        auto results = engine.QueryByPids(pids);

        CHECK(checkMatches(results, seenProcesses, pids, elementCount));
        CHECK(engine.Size() == elementCount);
    }
}

TEST_CASE("storage engine can retrieve added items", "[Sqlite3StorageEngine]") {

    std::vector<Event> mockSyscalls;
    mockSyscalls.emplace_back("sys_write");
    mockSyscalls.emplace_back("sys_read");
    mockSyscalls.emplace_back("sys_open");
    mockSyscalls.emplace_back("sys_mmap");
    
    Sqlite3StorageEngine engine;
    CHECK(engine.Initialize(mockSyscalls));
    CHECK(engine.Size() == 0);

    std::map<int, uint> resFreq;
    std::map<pid_t, uint> pidFreq;

    uint elementCount = 10000;
    auto pids = pidRange(1000, 1010);
    auto seenProcesses = storeNItems(engine, elementCount, 1000, 1010, -20, 20, mockSyscalls, resFreq, pidFreq);

    SECTION("The size of the data store matches the number of stored items.") {
        CHECK(engine.Size() == elementCount);
    }

    SECTION("Querying without any pids returns all items") {
        auto results = engine.QueryByPids({});
        CHECK(checkMatches(results, seenProcesses, pids, elementCount));
    }

    SECTION("Querying with a single pid return all items matching that pid") {
        auto results = engine.QueryByPid(1000);

        CHECK(checkMatches(results, seenProcesses, pids, pidFreq[1000]));
    }
    
    SECTION("Querying with a set of pids returns all items with matching pids") {
        uint count = pidFreq[1000] + pidFreq[1005] + pidFreq[1006] + pidFreq[1008];        
        
        auto results = engine.QueryByPids({1000, 1005, 1006, 1008});

        CHECK(checkMatches(results, seenProcesses, pids, count));
    }

    SECTION("Querying without any pid and specified page constraints returns expected results") {
        auto pageNum = 0;
        auto eventsPerPage = 100;
        auto results = engine.QueryByEventsinPage({}, pageNum++, eventsPerPage, ScreenConfiguration::time, true);
        CHECK(checkMatches(results, seenProcesses, pids, eventsPerPage));

        results = engine.QueryByEventsinPage({}, pageNum, eventsPerPage, ScreenConfiguration::time, true);
        CHECK(checkMatches(results, seenProcesses, pids, eventsPerPage));

        eventsPerPage = 200;
        results = engine.QueryByEventsinPage({}, pageNum, eventsPerPage, ScreenConfiguration::time, true);
        CHECK(checkMatches(results, seenProcesses, pids, eventsPerPage));
    }

    SECTION("Querying with a single pid and specified page constraints returns expected results") {
        auto pageNum = 0;
        auto eventsPerPage = 100;
        auto results = engine.QueryByEventsinPage({1000}, pageNum, eventsPerPage, ScreenConfiguration::time, true);
        CHECK((checkMatches(results, seenProcesses, pids, eventsPerPage) || checkMatches(results, seenProcesses, pids, pidFreq[1000])));
    }

    SECTION("Querying with a set of pids and specified page constraints returns expected results") {
        auto pageNum = 0;
        auto eventsPerPage = 100;
        auto results = engine.QueryByEventsinPage({1000, 1005, 1006, 1008}, pageNum, eventsPerPage, ScreenConfiguration::time, true);
        uint count = pidFreq[1000] + pidFreq[1005] + pidFreq[1006] + pidFreq[1008];
        CHECK((checkMatches(results, seenProcesses, pids, eventsPerPage) || checkMatches(results, seenProcesses, pids, count)));
    }

    SECTION("Querying with a result code returns all items with matching result code") {
        for(int res = -20; res <= 20; res++)
        {
            auto results = engine.QueryByResultCodeInTimespan(res);
            
            CHECK(checkMatches(results, seenProcesses, pids, resFreq[res]));
        }
    }

    SECTION("Multiple threads can query by pid from the storage engine at the same time") {
        std::vector<std::thread> threads;
        for(auto& pid: pids)
        {
            threads.push_back(std::thread([&]{
                auto results = engine.QueryByPid(pid);
                CHECK(checkMatches(results, seenProcesses, pids, pidFreq[pid]));
            }));
            threads.push_back(std::thread([&]{
                auto results = engine.QueryByPid(pid);
                CHECK(checkMatches(results, seenProcesses, pids, pidFreq[pid]));
            }));
        }
        for(auto& t: threads) t.join();
    }

    SECTION("Multiple threads can query by pids from the storage engine at the same time") {
        std::vector<std::thread> threads;
        for (int i = 0; i < 3; i++)
        {
            threads.push_back(std::thread([&]{
                auto results = engine.QueryByPids(pidRange(1000,1003));
                CHECK(checkMatches(results, seenProcesses, pids, pidFreq[1000] + pidFreq[1001] + pidFreq[1002]));
            }));
            threads.push_back(std::thread([&]{
                auto results = engine.QueryByPids(pidRange(1003,1006));
                CHECK(checkMatches(results, seenProcesses, pids, pidFreq[1003] + pidFreq[1004] + pidFreq[1005]));
            }));
            threads.push_back(std::thread([&]{
                auto results = engine.QueryByPids(pidRange(1006,1009));
                CHECK(checkMatches(results, seenProcesses, pids, pidFreq[1006] + pidFreq[1007] + pidFreq[1008]));
            }));
        }
        for(auto& t: threads) t.join();
    }

    SECTION("Multiple threads can query by result from the storage engine at the same time") {
        // TODO: There's some sort of race condition here. Solve it.
        std::vector<std::thread> threads;
        for(int res = -20; res <= 20; res++)
        {
            threads.push_back(std::thread([&, res]{
                auto results = engine.QueryByResultCodeInTimespan(res);
                CHECK(checkMatches(results, seenProcesses, pids, resFreq[res]));
            }));
            threads.push_back(std::thread([&, res]{
                auto results = engine.QueryByResultCodeInTimespan(res);
                CHECK(checkMatches(results, seenProcesses, pids, resFreq[res]));
            }));
        }
        for(auto& t: threads) t.join();
    }
}

TEST_CASE("storage engine can store and retrieve items at the same time", "[Sqlite3StorageEngine]") {

    std::vector<Event> mockSyscalls;
    mockSyscalls.emplace_back("sys_write");
    mockSyscalls.emplace_back("sys_read");
    mockSyscalls.emplace_back("sys_open");
    mockSyscalls.emplace_back("sys_mmap");
    
    Sqlite3StorageEngine engine;
    CHECK(engine.Initialize(mockSyscalls));
    CHECK(engine.Size() == 0);

    std::map<int, uint> resFreq;
    std::map<pid_t, uint> pidFreq;
    std::map<std::string, pid_t> seenProcesses;

    uint elementCount = 50;
    auto pids = pidRange(1000, 1010);   
    
    SECTION("Threads can query by pid while a writer fills the storage engine") {
        
        std::vector<std::thread> threads;

        threads.push_back(std::thread([&]{
            seenProcesses = storeNItems(engine, elementCount, 1000, 1010, -20, 20, mockSyscalls, resFreq, pidFreq);
            CHECK(engine.Size() == elementCount);
        }));

        threads.push_back(std::thread([&]{
            uint matchedTimes = 0;
            std::vector<MockTelemetry> results;
            while (matchedTimes < 2) 
            {
                REQUIRE_NOTHROW(results = engine.QueryByPids({}));
                if (results.size() == elementCount)
                    matchedTimes += 1;
            }
            CHECK(checkMatches(results, seenProcesses, pids, elementCount));
        }));

        for(auto& t: threads) t.join();
    }

    SECTION("Threads can query by resultcode while a writer fills the storage engine engine") {
        std::vector<std::thread> threads;

        threads.push_back(std::thread([&]{
            seenProcesses = storeNItems(engine, elementCount, 1000, 1010, -20, 20, mockSyscalls, resFreq, pidFreq);
            CHECK(engine.Size() == elementCount);
        }));

        threads.push_back(std::thread([&]{
            uint matchedTimes = 0;
            std::vector<MockTelemetry> results;
            while (matchedTimes < 2) 
            {
                uint accumulated = 0;
                bool allTrue = true;
                for(int res = -20; res <= 20; res++)
                {
                    REQUIRE_NOTHROW(results = engine.QueryByResultCodeInTimespan(res));
                    accumulated += results.size();
                    allTrue = allTrue && checkMatches(results, seenProcesses, pids, resFreq[res]);
                }

                if (accumulated == elementCount && allTrue)
                    matchedTimes += 1;
            }
        }));

        for(auto& t: threads) t.join();
    }
}