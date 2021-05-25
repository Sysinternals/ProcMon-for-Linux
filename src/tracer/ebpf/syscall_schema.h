// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include <experimental/filesystem>
#include <fstream>
#include <map>
#include <regex>
#include <string>
#include <vector>
#include <iostream>

namespace SyscallSchema
{
    enum class ArgTag
    {
        UNKNOWN, // Catch all for cases where arg type isn't known yet.
        INT,
        UNSIGNED_INT,
        SIZE_T,
        PID_T,
        LONG,
        UNSIGNED_LONG,
        CHAR_PTR,
        CONST_CHAR_PTR,
        FD,
        PTR,
        UINT32
    };

    struct SyscallSchema
    {
        // We should probably just be passing the syscall number back and forth instead.
        char syscallName[100];
        // It's probably not necessary to pass this info to kernel land and we can just store
        // it in an userland only map to be used by the UI.
        char argNames[6][100];
        // The key data structure necessary to infer what needs to be done.
        enum ArgTag types[6];
        int usedArgCount;
    };

    class Utils
    {
    public:
        static std::map<std::string, ArgTag> ArgTypeStringToArgTag;
        static std::map<std::string, int> SyscallNameToNumber;
        static std::map<int, std::string> SyscallNumberToName;
        static std::vector<std::string> Linux64PointerSycalls;

        static int GetSyscallNumberForName(const std::string& name)
        {
            auto maybeName = SyscallNameToNumber.find(name);
            if (maybeName != SyscallNameToNumber.end())
                return maybeName->second;
            else
                return -1;
        }

        static ArgTag GetArgTagForArg(const std::string &argumentName, const std::string &argumentType)
        {
            auto maybeTag = ArgTypeStringToArgTag.find(argumentType);
            if (maybeTag != ArgTypeStringToArgTag.end())
                return maybeTag->second;
            else if (argumentName == "fd")
                return ArgTag::FD;
            else if (argumentType.find("*") != std::string::npos)
            {
                return ArgTag::PTR;
            }
            else
                return ArgTag::UNKNOWN;
        }

        static std::vector<struct SyscallSchema> CollectSyscallSchema()
        {
            std::vector<SyscallSchema> schemas;
            schemas.reserve(350);

            std::regex filenameRegex("(.*)/sys_enter_([a-z0-9_]+)");
            // The line that contains this substring is up to where we skip to.
            std::regex syscall_nrRegex("__syscall_nr");
            // Regex to parse argument info.
            std::regex argFieldTypeName("(field:)([a-zA-Z0-9_\\s\\*]+)(;)");
            // Regex to parse arg and name
            std::regex argTypeAndName("([a-z\\* _]+)+ ([a-z_]+)$");

            for (const auto &fileEntry : std::experimental::filesystem::directory_iterator("/sys/kernel/debug/tracing/events/syscalls"))
            {
                std::string filepath = fileEntry.path();

                std::smatch match;
                if (std::regex_match(filepath, match, filenameRegex))
                {
                    struct SyscallSchema schema;

                    // Extract the syscall name using the filename regex.
                    // Messy, but we know we're looking exactly for the 2nd group.
                    std::strcpy(schema.syscallName, match[2].str().c_str());

                    // Change dir to format directory.
                    std::ifstream file(filepath + "/format");

                     // Skip all that we don't care about.
                    std::string line;
                    while (std::getline(file, line))
                        if (std::regex_search(line, match, syscall_nrRegex))
                            break;

                    // Start interpreting lines since everything but the last line is what we are about.
                    int argCount = 0;
                    while (std::getline(file, line))
                    {
                        if (std::regex_search(line, match, argFieldTypeName))
                        {
                            int i1 = line.find(":");
                            int i2 = line.find(";");
                            std::string res = line.substr(i1+1, i2-i1-1);
                            int lastPos = res.find_last_of(" ");

                            std::string argName = res.substr(lastPos+1, res.length()-lastPos-1);
                            std::string argType = res.substr(0, lastPos);
                            std::strcpy(schema.argNames[argCount], argName.c_str());
                            schema.types[argCount] = GetArgTagForArg(argName, argType);
                            argCount++;
                        }
                    }
                    // Make sure to record how many arguments we actually have for this syscall.
                    schema.usedArgCount = argCount;
                    schemas.push_back(schema);
                }
            }

            return schemas;
        }
    private:
        Utils();
    };
} // namespace SyscallSchema
