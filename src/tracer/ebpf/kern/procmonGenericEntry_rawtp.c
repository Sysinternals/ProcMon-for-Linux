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
#include <linux/types.h>
#endif

#include <stdint.h>
#include <bpf_helpers.h>
#include <bpf_core_read.h>
#include <asm/unistd_64.h>

#include <sysinternalsEBPF_common.h>
#include "procmonEBPF_common.h"
#include <sysinternalsEBPF_helpers.c>
#include "procmonEBPF_maps.h"


#define bpf_probe(dsc, size, src, str)                              \
    if (str)                                                        \
        bpf_probe_read_str((void*)dsc, size, (const void*)src);     \
    else                                                            \
        bpf_probe_read((void*)dsc, size, src);


// ------------------------------------------------------------------------------------------
// PopulateArguments
//
// Populates the event with the arguments for the syscall.
// ------------------------------------------------------------------------------------------
__attribute__((always_inline))
static inline int PopulateArguments(enum ProcmonArgTag type, unsigned long arg, struct SyscallEvent * event, unsigned int* offset_ptr)
{
    unsigned int len = 0;
    unsigned int str = 0;
    unsigned long src = arg;

    if (type == INT || type == LONG)
    {
        len = sizeof(long);
        src = (unsigned long)&arg;
    }
    else if (type == UNSIGNED_INT || type == UNSIGNED_LONG || type == SIZE_T || type == PID_T || type == PTR)
    {
        len = sizeof(unsigned long);
        src = (unsigned long)&arg;
    }
    else if (type == CHAR_PTR || type == CONST_CHAR_PTR)
    {
        len = MAX_BUFFER / 6;
        str = 1;
    }
    else if (type == FD)
    {
        len = MAX_BUFFER / 6;
        str = 1;
        char buff[len];
    }
    else if (type == UINT32)
    {
        len = sizeof(uint32_t);
        src = (unsigned long)&arg;
    }
    else
    {
        // Do nothing here....
    }

    if (*offset_ptr + len >= MAX_BUFFER)
        return -1;

    if (!src)
        return -1;

    bpf_probe(event->buffer + *offset_ptr, len, (void *)src, str)
    *offset_ptr += len;

    return 0;
}

// ------------------------------------------------------------------------------------------
// set_eventArgs
//
// Populates the event with the arguments for the syscall.
// ------------------------------------------------------------------------------------------
__attribute__((always_inline))
static inline bool set_eventArgs(unsigned long *a, const struct pt_regs *regs)
{
    int ret = 0;
    ret |= bpf_probe_read(&a[0], sizeof(a[0]), &SYSCALL_PT_REGS_PARM1(regs));
    ret |= bpf_probe_read(&a[1], sizeof(a[1]), &SYSCALL_PT_REGS_PARM2(regs));
    ret |= bpf_probe_read(&a[2], sizeof(a[2]), &SYSCALL_PT_REGS_PARM3(regs));
    ret |= bpf_probe_read(&a[3], sizeof(a[3]), &SYSCALL_PT_REGS_PARM4(regs));
    ret |= bpf_probe_read(&a[4], sizeof(a[4]), &SYSCALL_PT_REGS_PARM5(regs));
    ret |= bpf_probe_read(&a[5], sizeof(a[5]), &SYSCALL_PT_REGS_PARM6(regs));
    if (!ret)
        return true;
    else
        return false;
}


SEC("raw_tracepoint/sys_enter")
__attribute__((flatten))
int genericRawEnter(struct bpf_our_raw_tracepoint_args *ctx)
{
    uint64_t *state = NULL;
    int ret = 0;
    int rkey = 0;
    uint32_t syscall = ctx->args[1];
    uint32_t cpuId = bpf_get_smp_processor_id();
    uint64_t pidTid = bpf_get_current_pid_tgid();
    uint64_t pid = pidTid >> 32;
    argsStruct* eventArgs = NULL;
    struct pt_regs* regs = NULL;

    //
    // Check to make sure we are in a running state
    //
    state = (uint64_t*)bpf_map_lookup_elem(&runstate, &rkey);
    if(state==NULL)
    {
        return -1;
    }

    //
    // Get the syscall details
    //
    struct SyscallSchema* schema = bpf_map_lookup_elem(&syscalls, &syscall);
    if(schema == NULL)
    {
        BPF_PRINTK("[genericRawEnter] Failed to get syscall schema %d.", syscall);
        return -1;
    }

    //
    // Get temp storage to build up the event
    //
    struct SyscallEvent* sysEntry = bpf_map_lookup_elem(&eventStorageMap, &cpuId);
    if (!sysEntry)
    {
        BPF_PRINTK("[genericRawEnter] Failed to get storage for syscall event.");
        return 0;
    }

    //
    // Populate the event
    //
    sysEntry->pid = pid;
    sysEntry->sysnum = ctx->args[1];
    bpf_get_current_comm(&sysEntry->comm, sizeof(sysEntry->comm));
    sysEntry->userStackCount = bpf_get_stack(ctx, &sysEntry->userStack, MAX_STACK_FRAMES * sizeof(uint64_t), BPF_F_USER_STACK) / sizeof(uint64_t);
    sysEntry->timestamp = bpf_ktime_get_ns();

    regs = (struct pt_regs *)ctx->args[0];
    unsigned long a[8];
    if (!set_eventArgs(a, regs))
    {
        BPF_PRINTK("[genericRawEnter] set_eventArgs failed\n");
    }

    unsigned int offset = 0;
    for (int i = 0; i < 6; i++)
    {
        if(PopulateArguments(schema->types[i], a[i], sysEntry, &offset) || i >= schema->usedArgCount)
        {
            break;
        }
    }

    //
    // Store the event to be retrieved and updated on exit
    //
    if ((ret = bpf_map_update_elem(&syscallsMap, &pidTid, sysEntry, BPF_ANY)) != UPDATE_OKAY)
    {
        BPF_PRINTK("ERROR, HASHMAP: failed to update syscalls map, %ld\n", ret);
    }

    return 0;
}