// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "event_formatter.h"
#include "../logging/easylogging++.h"
#include "errno.h"
#include <iomanip>


std::string EventFormatter::GetTimestamp(ITelemetry &event)
{
    return CalculateDeltaTimestamp(event.timestamp);
}

std::string EventFormatter::GetPID(ITelemetry &event)
{
    return std::to_string(event.pid);
}

std::string EventFormatter::GetProcess(ITelemetry &event)
{
    return event.processName;
}

std::string EventFormatter::GetOperation(ITelemetry &event)
{
    return event.syscall;
}

std::string EventFormatter::GetDuration(ITelemetry &event)
{
    return std::to_string((double) event.duration/1000000);
}

std::string EventFormatter::GetResult(ITelemetry &event)
{
    std::vector<std::string> pointerSycalls = config->getPointerSyscalls();
    if(event.result >= 0)
    {
        for(int i = 0; i < pointerSycalls.size(); i++)
        {
            if(event.syscall == pointerSycalls[i])
            {
                std::stringstream stream;
                stream << std::setfill('0') << std::setw(sizeof(uint64_t)*2) << std::hex << event.result;
                return "0x" + stream.str();
            }
        }
        return std::to_string(event.result);
    }
    else
    {
        return std::to_string(event.result) + " (" + strerror(-1 * event.result) + ")";
    }
}

std::string EventFormatter::GetDetails(ITelemetry &event)
{
    return DecodeArguments(event);
}


std::string EventFormatter::CalculateDeltaTimestamp(uint64_t ebpfEventTimestamp)
{
    std::string deltaTimestamp;

    // calculate delta from beginning of procmon for timestamp column
    uint64_t delta = ebpfEventTimestamp - (config->GetStartTime());


    unsigned hour = delta / 3600000000000;
    delta = delta % 3600000000000;
    unsigned min = delta / 60000000000;
    delta = delta % 60000000000;
    unsigned sec = delta / 1000000000;
    delta = delta % 1000000000;
    unsigned millisec = delta / 1000000;

    deltaTimestamp += " +" + std::to_string(hour) + ":" +
        std::to_string(min) + ":" +
        std::to_string(sec) + "." +
        std::to_string(millisec);

    return deltaTimestamp;
}

std::string EventFormatter::DecodeArguments(ITelemetry &event)
{
    std::string args = "";

    std::vector<struct SyscallSchema::SyscallSchema>& schema = config->GetSchema();

    // Find the schema item
    int index = FindSyscall(event.syscall);
    SyscallSchema::SyscallSchema item = schema[index];

    int readOffset = 0;
    for(int i=0; i<item.usedArgCount; i++)
    {
        args+=item.argNames[i];
        args+="=";

        if(item.types[i]==SyscallSchema::ArgTag::INT || item.types[i]==SyscallSchema::ArgTag::LONG)
        {
            long val = 0;
            int size = sizeof(long);
            memcpy(&val, event.arguments+readOffset, size);
            args+=std::to_string(val);
            readOffset+=size;
        }
        else if(item.types[i]==SyscallSchema::ArgTag::UINT32)
        {
            uint32_t val = 0;
            int size = sizeof(uint32_t);
            memcpy(&val, event.arguments+readOffset, size);
            args+=std::to_string(val);
            readOffset+=size;
        }
        else if (item.types[i] == SyscallSchema::ArgTag::UNSIGNED_INT || item.types[i] == SyscallSchema::ArgTag::UNSIGNED_LONG || item.types[i] == SyscallSchema::ArgTag::SIZE_T || item.types[i] == SyscallSchema::ArgTag::PID_T)
        {
            unsigned long val = 0;
            int size = sizeof(unsigned long);
            memcpy(&val, event.arguments+readOffset, size);
            args+=std::to_string(val);
            readOffset+=size;
        }
        else if (item.types[i] == SyscallSchema::ArgTag::CHAR_PTR || item.types[i] == SyscallSchema::ArgTag::CONST_CHAR_PTR)
        {
            if(event.syscall.compare("read") == 0)
            {
                args += "{in}";
            }
            else if (event.syscall.compare("write") == 0)
            {
                int size = MAX_BUFFER / 6;
                std::stringstream ss;

                // check to see if our preview buffer is larger then result of write 
                if(size > event.result)
                {
                    size = event.result;
                }

                uint8_t buff[size] = {};
                memcpy(buff, event.arguments + readOffset, size);
                readOffset += size;

                for(int i = 0; i < size; i++)
                {
                    ss << std::setfill('0') << std::setw(2) << std::hex << (uint32_t)buff[i] << " ";
                }

                args += ss.str();
            }
            else
            {
                int size = MAX_BUFFER / 6;
                uint8_t buff[size] = {};
                std::stringstream ss;


                memcpy(buff, event.arguments + readOffset, size);
                readOffset += size;

                for(int i = 0; i < size; i++)
                {
                    ss << std::hex << (uint32_t)buff[i] << " ";
                }
                args += ss.str();
            }
        }
        else if (item.types[i] == SyscallSchema::ArgTag::FD)
        {
            int size=MAX_BUFFER/6;
            char buff[size] = {};
            memcpy(buff, event.arguments+readOffset, size);
            readOffset+=size;
            args+=buff;
        }
        else if (item.types[i] == SyscallSchema::ArgTag::PTR)
        {
            unsigned long val = 0;
            int size = sizeof(unsigned long);
            memcpy(&val, event.arguments+readOffset, size);
            if(val==0)
            {
                args+="NULL";
            }
            else
            {
                args+="0x";
                std::stringstream ss;
                ss << std::hex << val;
                args+=ss.str();
            }
            readOffset+=size;

        }
        else
        {
            args+="{}";
        }

        args+="  ";
    }

    return args;
}

int EventFormatter::FindSyscall(std::string& syscallName)
{
    std::vector<struct SyscallSchema::SyscallSchema>& schema = config->GetSchema();

    int i = 0;
    for(auto& syscall : schema)
    {
        if(syscallName.compare(syscall.syscallName)==0)
        {
            return i;
        }
        i++;
    }

    return -1;
}
