/*
    Procmon-for-Linux

    Copyright (c) Microsoft Corporation

    All rights reserved.

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#ifndef PROCMON_EBPF_COMMON_H
#define PROCMON_EBPF_COMMON_H

#define PROCMON_EBPF

#define PACKET_SIZE             128
#define UDP_HASH_SIZE           (128 * 1024)


#define LINUX_MAX_EVENT_SIZE (65536 - 24)

// defining file mode locally to remove requirement for heavy includes.
// note that these *could* change, *but really aren't likely to*!
#define S_IFMT      00170000
#define S_IFREG      0100000
#define S_IFBLK      0060000
#define S_IFSOCK     0140000

#define MAX_BUFFER 128
#define MAX_STACK_FRAMES 32
#define MAX_PROC 512

struct SyscallEvent
{
    pid_t pid;
    uint32_t sysnum;
    uint64_t timestamp;
    uint64_t duration_ns;
    uint64_t userStack[MAX_STACK_FRAMES];
    uint64_t userStackCount;
    uint64_t ret;
    char comm[16];
    unsigned char buffer [MAX_BUFFER];
};

enum ProcmonArgTag
{
    NOTKNOWN, // Catch all for cases where arg type isn't known yet.
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
    enum ProcmonArgTag types[6];
    int usedArgCount;
};

// create a map to hold the event as we build it - too big for stack
// one entry per cpu
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(uint32_t));
    __uint(value_size, LINUX_MAX_EVENT_SIZE);
    __uint(max_entries, MAX_PROC);
} eventStorageMap SEC(".maps");

// create a map to hold the args as we build it - too big for stack
// one entry per cpu
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, uint32_t);
    __type(value, argsStruct);
    __uint(max_entries, MAX_PROC);
} argsStorageMap SEC(".maps");


// create a map to hold the packet as we access it - eBPF doesn't like
// arbitrary access to stack buffers
// one entry per cpu
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(uint32_t));
    __uint(value_size, PACKET_SIZE);
    __uint(max_entries, MAX_PROC);
} packetStorageMap SEC(".maps");

// create a map to hold the syscall information
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 345);
    __type(key, uint32_t);
    __type(value, sizeof(struct SyscallSchema));
} syscallsMap SEC(".maps");

#endif
