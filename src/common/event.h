// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

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