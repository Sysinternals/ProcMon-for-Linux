/*
    Procmon-for-Linux

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#ifndef TRACER_ENGINE_H
#define TRACER_ENGINE_H

#include <functional>
#include <memory>
#include <map>

#include "../common/event.h"
#include "../storage/storage_engine.h"

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

    virtual void Initialize() {};

    virtual void AddEvent(Event eventToTrace) {};
    virtual void AddEvent(std::vector<Event> eventsToTrace) {};

    virtual void AddPids(std::vector<int> pidsToTrace) {};

    virtual void RemoveEvent(Event eventToRemove) {};
    virtual void RemoveEvent(std::vector<Event> eventsToRemove) {};
    virtual void SetRunState(int runState) { RunState = runState; }
    virtual int GetRunState() { return RunState; }
    virtual void Cancel() {}
};

#endif // TRACER_ENGINE_H