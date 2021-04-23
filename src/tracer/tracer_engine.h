// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef TRACER_ENGINE_H
#define TRACER_ENGINE_H

#include <functional>
#include <memory>
#include <map>

#include "../common/event.h"
#include "../storage/storage_engine.h"

#define TRACER_RUNNING          0
#define TRACER_SUSPENDED        1
#define TRACER_STOP             2

class ITracerEngine
{
protected:
    std::shared_ptr<IStorageEngine> _storageEngine;
    std::vector<Event> _targetEvents;
    int RunState; 
    
public:
    ITracerEngine() {};
    ITracerEngine(std::shared_ptr<IStorageEngine> storageEngine, std::vector<Event> targetEvents) : _storageEngine(storageEngine) { _targetEvents = targetEvents; };
    virtual ~ITracerEngine() {};

    virtual void AddEvent(Event eventToTrace) {};
    virtual void AddEvent(std::vector<Event> eventsToTrace) {};

    virtual void AddPids(std::vector<int> pidsToTrace) {};

    virtual void RemoveEvent(Event eventToRemove) {};
    virtual void RemoveEvent(std::vector<Event> eventsToRemove) {};
    virtual void SetRunState(int runState) { RunState = runState; }
    virtual int GetRunState() { return RunState; }
};

#endif // TRACER_ENGINE_H