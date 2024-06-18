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

#ifndef PROCMON_EBPF_MAPS_H
#define PROCMON_EBPF_MAPS_H

#include "procmonEBPF_common.h"

// create a map to hold the event as we build it - too big for stack
// one entry per cpu
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, uint32_t);
    __type(value, struct SyscallEvent);
    __uint(max_entries, MAX_PROC);
} eventStorageMap SEC(".maps");

// create a map to hold the syscall information
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, uint64_t);
    __type(value, struct SyscallEvent);
} syscallsMap SEC(".maps");

// Procmon config
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, uint32_t);
    __type(value, uint64_t);
    __uint(max_entries, CONFIG_ITEMS);
} configuration SEC(".maps");

// Procmon PIDS
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, uint32_t);
    __type(value, uint64_t);
    __uint(max_entries, MAX_PIDS);
} pids SEC(".maps");

// Procmon runstate
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, uint32_t);
    __type(value, uint64_t);
    __uint(max_entries, 1);
} runstate SEC(".maps");

// Procmon syscalls
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, uint32_t);
    __type(value, struct SyscallSchema);
    __uint(max_entries, 345);
} syscalls SEC(".maps");

#endif
