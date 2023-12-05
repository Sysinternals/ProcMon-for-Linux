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


#ifdef EBPF_CO_RE
#include "vmlinux.h"
#else
#include <linux/version.h>
#include <linux/bpf.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/fcntl.h>
#include <sys/socket.h>
#include <linux/string.h>
#include <asm/ptrace.h>
#endif

#include <sysinternalsEBPF_common.h>
#include <stdint.h>
#include <bpf_helpers.h>
#include <bpf_core_read.h>
#include <asm/unistd_64.h>
#include <sysinternalsEBPFshared.h>
//#include "sysmon_defs.h"

#define LINUX_MAX_EVENT_SIZE (65536 - 24)

// defining file mode locally to remove requirement for heavy includes.
// note that these *could* change, *but really aren't likely to*!
#define S_IFMT      00170000
#define S_IFREG      0100000
#define S_IFBLK      0060000
#define S_IFSOCK     0140000

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

// create a map to hold the UDP recv age information
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, UDP_HASH_SIZE);
    __type(key, uint64_t);
    __type(value, uint64_t);
} UDPrecvAge SEC(".maps");


// create a map to hold the UDP send age information
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, UDP_HASH_SIZE);
    __type(key, uint64_t);
    __type(value, uint64_t);
} UDPsendAge SEC(".maps");


#endif
