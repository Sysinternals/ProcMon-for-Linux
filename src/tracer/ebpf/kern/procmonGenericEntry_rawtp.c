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


// store the syscall arguments from the registers in the event
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
    {BPF_PRINTK("sys_enter\n");}

    uint32_t cpuId = bpf_get_smp_processor_id();
    uint64_t pidTid = bpf_get_current_pid_tgid();
    uint64_t pid = pidTid >> 32;
    argsStruct* eventArgs = NULL;
    struct pt_regs* regs = NULL;

    eventArgs = bpf_map_lookup_elem(&argsStorageMap, &cpuId);
    if (!eventArgs)
    {
        return 0;
    }

    regs = (struct pt_regs *)ctx->args[0];
    if (!set_eventArgs(eventArgs->a, regs))
    {
        BPF_PRINTK("set_eventArgs failed\n");
    }

    struct SyscallEvent* sysEntry = bpf_map_lookup_elem(&eventStorageMap, &cpuId);
    if(!sysEntry)
    {
        BPF_PRINTK("sys_enter: FAIL 1\n");
        return 0;
    }

    sysEntry->pid = pid;
    sysEntry->sysnum = ctx->args[1];
    bpf_get_current_comm(&sysEntry->comm, sizeof(sysEntry->comm));
    sysEntry->userStackCount = bpf_get_stack(ctx, &sysEntry->userStack, MAX_STACK_FRAMES * sizeof(uint64_t), BPF_F_USER_STACK) / sizeof(uint64_t);
    sysEntry->timestamp = bpf_ktime_get_ns();


    eventOutput((void*)ctx, &eventMap, BPF_F_CURRENT_CPU, sysEntry, sizeof(struct SyscallEvent));

    return 0;
}