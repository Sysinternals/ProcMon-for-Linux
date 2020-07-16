// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include <string>

#include "../../common/printable.h"

#define MAX_BUFFER 128
#define MAX_STACK_FRAMES 32

struct SyscallEvent
{
    pid_t pid;
    uint32_t sysnum;
    uint64_t timestamp;
    uint64_t duration_ns;
    uint64_t userStack[MAX_STACK_FRAMES];
    uint64_t userStackCount;
    uint64_t kernelStack[MAX_STACK_FRAMES];
    uint64_t kernelStackCount;
    uint64_t ret;
    char comm[16];
    unsigned char buffer [MAX_BUFFER]; 
};