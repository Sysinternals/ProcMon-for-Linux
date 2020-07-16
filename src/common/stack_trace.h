// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef STACK_TRACE_H
#define STACK_TRACE_H

#include <string>
#include <vector>
#include <sstream>

struct StackTrace
{
    std::vector<uint64_t> kernelIPs;
    std::vector<std::string> kernelSymbols;
    std::vector<uint64_t> userIPs;
    std::vector<std::string> userSymbols;

    StackTrace() {}

    std::string Serialize()
    {
        std::string ret;

        ret += std::to_string(userIPs[0]) + "$" + userSymbols[0];

        for(int i = 1; i < userIPs.size(); i++)
        {
            ret += ";" + std::to_string(userIPs[i]) + "$" + userSymbols[i];
        }
        return ret;
    }

    void Inflate(std::string blob) 
    {
        std::string token;
        std::stringstream stream(blob);

        while(std::getline(stream, token, ';'))
        {
            int location = token.find('$');

            userIPs.push_back(std::stoull(token.substr(0, location)));
            userSymbols.push_back(token.substr(location+1, token.size()));
        }
    }

};

#endif // STACK_TRACE_H
