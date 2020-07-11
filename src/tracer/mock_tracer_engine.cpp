// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <functional>
#include <random>
#include <sstream>

#include "mock_tracer_engine.h"

MockTracerEngine::MockTracerEngine(std::shared_ptr<IStorageEngine> storageEngine, std::vector<Event> targetEvents) : ITracerEngine(storageEngine, targetEvents)
{
    std::default_random_engine  generator;
    std::uniform_real_distribution<float> distribution(100, 9999);
    auto dice = std::bind(distribution, generator);
    for (size_t i = 0; i < 1000; ++i)
    {
        int foo = (int)std::ceil(dice());
        std::stringstream ss;
        ss << "tel " << foo;
        MockTelemetry tel { .pid = foo, .stackTrace = {}, .comm = ss.str(), .processName = ss.str() };
        _storageEngine->Store(tel);
    }

    _storageEngine->Store({ .pid = 101, .stackTrace = {}, .comm = "/usr/bin/local/my.exe", .processName = "my.exe" });
}
