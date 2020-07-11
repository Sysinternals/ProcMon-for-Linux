// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef MOCK_TRACER_ENGINE_H
#define MOCK_TRACER_ENGINE_H

#include <functional>
#include <random>
#include <sstream>
#include <vector>

#include "tracer_engine.h"
#include "../storage/mock_storage_engine.h"

class MockTracerEngine : public ITracerEngine
{
public:
    MockTracerEngine(std::shared_ptr<IStorageEngine> storageEngine, std::vector<Event> targetEvents);
};

#endif // MOCK_TRACER_ENGINE_H