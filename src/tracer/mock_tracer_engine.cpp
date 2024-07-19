/*
    Procmon-for-Linux

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

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
