/*
    Procmon-for-Linux

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#pragma once

#include <iostream>
#include <string>

#include "printable.h"
#include "cli_utils.h"

class Event : public IPrintable
{
  public:
    Event(std::string eventName)
    {
        if (!IsValid(eventName))
        {
            // TODO error handling
            std::cerr << "Event::\"" << eventName << "\" is an invalid trace event" << std::endl;

            // re-enable cursor before exiting Procmon
            system("setterm -cursor on");

            // TODO: something better?
            exit(-1);
        }
        _name = eventName;
    }

    const std::string Name() const { return _name; }

    static bool IsValid(std::string event)
    {
        // TODO
        return true;
    }

    static bool IsValid(Event event)
    {
        // TODO
        return IsValid(event.Name());
    }

    const std::string Print() const override { return _name; }

    bool operator <(const Event& e)
    {
        if(_name < e.Name())
            return true;

        return false;
    }

  private:
    std::string _name;
};