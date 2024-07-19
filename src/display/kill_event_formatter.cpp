/*
    Procmon-for-Linux

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include "kill_event_formatter.h"
#include "../logging/easylogging++.h"


std::string KillEventFormatter::GetDetails(ITelemetry event)
{
    std::string details;
    long pid = 0;
    long signal = 0;

    // First get the PID
    int size = sizeof(long);
    memcpy(&pid, event.arguments, size);

    // Next, the signal #
    memcpy(&signal, event.arguments+sizeof(long), size);

    if(signal<signalmap.size())
    {
        std::string signalname = signalmap[signal];
        details = signalname + " sent to process ID " + std::to_string(pid);
    }
    else
    {
        details = "Signal " + std::to_string(signal) + " send to process ID " + std::to_string(pid);
    }

    return details;
}


