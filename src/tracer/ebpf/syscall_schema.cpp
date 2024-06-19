/*
    Procmon-for-Linux

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include "syscall_schema.h"
#include "syscalls.h"

std::map<std::string, ProcmonArgTag> Utils::ArgTypeStringToArgTag = {
        {"fd", ProcmonArgTag::FD},
        {"int", ProcmonArgTag::INT},
        {"unsigned int", ProcmonArgTag::UNSIGNED_INT},
        {"size_t", ProcmonArgTag::SIZE_T},
        {"pid_t", ProcmonArgTag::PID_T},
        {"long", ProcmonArgTag::LONG},
        {"unsigned long", ProcmonArgTag::UNSIGNED_LONG},
        {"char *", ProcmonArgTag::CHAR_PTR},
        {"const char *", ProcmonArgTag::CONST_CHAR_PTR},
        {"u32", ProcmonArgTag::UINT32},
        {"unsigned", ProcmonArgTag::UNSIGNED_INT},
        {"umode_t", ProcmonArgTag::INT}
    };

std::vector<std::string> Utils::Linux64PointerSycalls = {
        "mmap",
        "mremap",
        "shmat",
        "getcwd"
    };
