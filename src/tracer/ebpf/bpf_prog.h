// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include <string>

const std::string sys_enter_bpf_prog_name = "prog";
const std::string sys_exit_bpf_prog_name = "prog_exit";

const std::string bpf_prog = R"(
    #ifdef asm_volatile_goto
    #undef asm_volatile_goto
    #endif
    #define asm_volatile_goto(x...) asm volatile("invalid use of asm_volatile_goto")
    
    // There must be a way to format the string from c++ code.
    #define MAX_BUFFER 128
    #define MAX_STACK_FRAMES 32

    #define TRACER_STOP            2
    #define TRACER_SUSPENDED       1
    #define TRACER_RUNNING         0

    #define MAX_PIDS            10

    // Counter field randomization.
    // #define randomized_struct_fields_start  struct {
    // #define randomized_struct_fields_end    };
    #include <uapi/linux/bpf.h>
    #include <linux/dcache.h>
    #include <linux/err.h>
    #include <linux/fdtable.h>
    #include <linux/sched.h>
    #include <linux/fdtable.h>
    #include <linux/fs.h> 
    #include <linux/fs_struct.h>
    #include <linux/dcache.h>
    #include <linux/slab.h>

    enum ArgTag {
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

    struct SyscallSchema {
        // We should probably just be passing the syscall number back and forth instead.
        char syscallName [100];
        // It's probably not necessary to pass this info to kernel land and we can just store
        // it in an userland only map to be used by the UI.
        char argNames[6][100];
        // The key data structure necessary to infer what needs to be done.
        enum ArgTag types[6];
        int  usedArgCount;
    };

    struct SyscallEvent {
        pid_t pid;
        u32 sysnum;
        u64 timestamp;
        u64 duration_ns;
        u64 userStack[MAX_STACK_FRAMES];
        u64 userStackCount;
        u64 kernelStack[MAX_STACK_FRAMES];
        u64 kernelStackCount;
        // u64 userStackKey;
        // u64 kernelStackKey;
        u64 ret;
        char comm[16];
        unsigned char buffer [MAX_BUFFER]; 
    };

    BPF_PERF_OUTPUT(events);
    BPF_STACK_TRACE(stack_traces, 10240);
    BPF_HASH(enter_events, u64, struct SyscallEvent, 1000);
    BPF_TABLE("extern", int, int, config, 1);
    BPF_TABLE("extern", int, int, pids, MAX_PIDS);    
    BPF_TABLE("extern", int, int, runstate, 1);
    BPF_TABLE("extern", int, struct SyscallSchema, syscalls, 345);
    BPF_PERCPU_ARRAY(scratch, struct SyscallEvent, 1);

    #define bpf_probe(dsc, size, src, str)                              \
        if (str)                                                        \
            bpf_probe_read_str((void*)dsc, size, (const void*)src);     \
        else                                                            \
            bpf_probe_read((void*)dsc, size, src);      

    static int handle_arg(enum ArgTag type, unsigned long arg, struct SyscallEvent * event, unsigned int* offset_ptr)
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
            // Handle FD.
            // FIX ME: Maybe it's worth considering the case when a path couldn't be retrieved but we still want to return
            // the rest of the arg infos.
            len = MAX_BUFFER / 6;
            str = 1;
            char buff[len];
            // src = retrieve_path((unsigned int)src, &buff, len, f);
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

    static bool compare_to_self(const char* name)
    {
        bool ret=false; 
        char* procmon = "procmon";

        int i;
        for(i = 0; i < 7; i++)
        {
            if(name[i]=='\0')
            {
                break;
            }

            if(name[i]!=procmon[i])
            {
                break;
            }
        }
        if(i==7)
        {
            ret=true;
        }

        return ret; 
    }

    // Check to see if user has suspended the collection from the TUI. If so, we return false and ignore the trace.
    // Note: If we fail to get the runstate value we just assume we need to keep tracing.
    static bool IsRunning()
    {
        int runStateKey = 0;
        u32* runState = runstate.lookup(&runStateKey);
        if(runState!=NULL)
        {
            if(*runState==TRACER_SUSPENDED || *runState==TRACER_STOP)
            {
                return false; 
            }
            else
            {
                return true;
            }
        }

        return true;
    }

    // Checks to see if user has specified a pid filter.
    static bool HasPidFilter()
    {
        bool ret=false; 
        u32 key = 0; 
        u32* p = pids.lookup(&key);
        if(p)
        {
            if((*p)!=-1)
            {
                ret=true;
            }
        }

        return ret; 
    }

    // Check to see if the specified pid matches any of the pid filters. 
    // If we dont have any filters the lookup will fail fast due to -1 check. 
    static bool PidFilterMatch(int pid)
    {
        for(int i=0; i<MAX_PIDS; i++)
        {
            u32 key = i; 
            u32* p = pids.lookup(&key);
            if(p)
            {
                if((*p)==-1)
                {
                    break;              // we can bail early since -1 indicates we've reached the end of the pid items in the map
                }

                if((*p)==pid)
                {
                    return true;
                }
            }
            else
            {
                break;
            }
        }

        return false;
    }

    int prog (struct tracepoint__raw_syscalls__sys_enter *args)
    {
        // Check to see if we should be tracing at all (suspended). 
        if(IsRunning()==false)
        {
            return 0; 
        }

        u64 pid = bpf_get_current_pid_tgid();

        if(HasPidFilter()==true)
        {
            // Check to see if pid matches any in the filter list
            if(PidFilterMatch((u32)pid) == false)
            {
                return 0;
            }
        }

        u32 key = 0;
        // u32* userland_pid = config.lookup(&key);
        // if (!userland_pid)
        //     return -1;
        
        key = (u32)(args->id);
        struct SyscallSchema* schema = syscalls.lookup(&key);
        if (!schema)
        {
            return -1;
        }

        int zero = 0;
        struct SyscallEvent* event = scratch.lookup(&zero);
        if (!event)
            return -1;

        // struct SyscallEvent event = {};
        event->pid = pid;
        event->sysnum = key;
        event->userStackCount = bpf_get_stack(args, &event->userStack, MAX_STACK_FRAMES * sizeof(u64), BPF_F_USER_STACK) / sizeof(u64);
        event->kernelStackCount = bpf_get_stack(args, event->kernelStack, MAX_STACK_FRAMES * sizeof(u64), 0) / sizeof(u64);
        // event->userStackKey = stack_traces.get_stackid(args, BPF_F_REUSE_STACKID | BPF_F_USER_STACK);
        // event->kernelStackKey = stack_traces.get_stackid(args, BPF_F_REUSE_STACKID);
        event->timestamp = bpf_ktime_get_ns();
        bpf_get_current_comm(&event->comm, sizeof(event->comm));

        if(compare_to_self(event->comm)==false)
        {
            unsigned int offset = 0;

            #pragma unroll
            for (int i = 0; i < 6; i++)
                if(handle_arg(schema->types[i], args->args[i], event, &offset) || i >= schema->usedArgCount)
                    break;

            enter_events.update(&pid, event);
        }

        return 0;
    }

    int prog_exit(struct tracepoint__raw_syscalls__sys_exit *args)
    {
        // Check to see if we should be tracing. 
        if(IsRunning()==false)
        {
            return 0; 
        }

        u64 pid = bpf_get_current_pid_tgid();

        if(HasPidFilter()==true)
        {
            // Check to see if pid matches any in the filter list
            if(PidFilterMatch(pid >> 32)==false)
            {
                return 0;
            }
        }

        struct SyscallEvent *event = enter_events.lookup(&pid);
        if (event)
        {
            bpf_get_current_comm(&event->comm, sizeof(event->comm));
            if(compare_to_self(event->comm)==false)
            {
                event->ret = args->ret;
                event->duration_ns = bpf_ktime_get_ns() - event->timestamp;
                events.perf_submit(args, event, sizeof(struct SyscallEvent));
            }
        }

        return 0;
    }
)";