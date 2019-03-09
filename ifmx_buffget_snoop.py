#!/usr/bin/python3
#
# fmx_buffget_snoop.py  Trace buffget() library function.
#               For Linux, uses BCC, eBPF. Embedded C.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 9-Mar-2019   Nagaraju Inturi Created this.
#
# USAGE: 
# ./ifmx_buffget_snoop.py
#TIME(s)        COMM           PID    PHYSADDR       LAT(us)
#0.000000000    oninit           2714   5:595            20.01
#0.000057000    oninit           2714   5:2               8.38
#0.000075000    oninit           2714   5:2               7.91
#0.000136000    oninit           2714   5:561             7.29
#0.000180000    oninit           2714   5:2              35.84
#0.000206000    oninit           2714   5:560             6.41
#0.000218000    oninit           2714   5:2               6.13

from __future__ import print_function
from bcc import BPF
import ctypes as ct
from os import getpid
import sys
import os

#
#if len(sys.argv) < 2:
#    print("USAGE: buffgetsnoop PID")
#    exit()
pid = 0
#pid = sys.argv[1]

# load BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>        /* For TASK_COMM_LEN */

// define output data structure in C
struct data_t {
    u32 pg_offset;
    u32 pg_chunk;
    u64 ts;
    u64 delta;
    u32 pid;
    char name[TASK_COMM_LEN];
};

typedef struct ifx_physaddr {
    u32 pg_offset;            
    u32 pg_chunk;
    u64 ts;
} ifx_physaddr_t;
BPF_HASH(bufmap, u64, ifx_physaddr_t);
BPF_PERF_OUTPUT(events);

int do_entry(struct pt_regs *ctx) {
    if (!PT_REGS_PARM2(ctx))
        return 0;

    u64 bp = PT_REGS_FP(ctx);
/*
    u32 pid = bpf_get_current_pid_tgid();
    if (pid != PID)
        return 0;
*/

    ifx_physaddr_t  physaddr = {0};
    u64 paddr = PT_REGS_PARM2(ctx);
    if (!paddr)
         return 0;
    physaddr.pg_offset = (int)paddr;
    physaddr.pg_chunk = (int)(paddr>>32);
    physaddr.ts = bpf_ktime_get_ns();
    bufmap.update(&bp, &physaddr);
    //bpf_trace_printk("%d:%d\\n", physaddr.pg_chunk, physaddr.pg_offset);

    return 0;
}
int do_return(struct pt_regs *ctx)
{
    u64 bp = PT_REGS_FP(ctx);
    ifx_physaddr_t *physaddr = bufmap.lookup(&bp);

    if (physaddr) {
        u64 ts = bpf_ktime_get_ns();
        struct data_t data = {0};
        data.pg_offset = physaddr->pg_offset;
        data.pg_chunk = physaddr->pg_chunk;
        data.delta = ts - physaddr->ts;
        data.ts = ts/1000; 
        data.pid = bpf_get_current_pid_tgid();
        bpf_get_current_comm(&data.name, sizeof(data.name));
        events.perf_submit(ctx, &data, sizeof(data));
        bufmap.delete(&bp);
    }

    return 0;
};
"""
#bpf_text = bpf_text.replace('PID', pid)
b = BPF(text=bpf_text)
oninitpath=str(os.environ.get('INFORMIXDIR'))+"/bin/oninit"
funcname="buffget"
b.attach_uprobe(name=oninitpath, sym=funcname, fn_name="do_entry")
b.attach_uretprobe(name=oninitpath, sym=funcname, fn_name="do_return")


TASK_COMM_LEN = 16  # linux/sched.h
class Data(ct.Structure):
    _fields_ = [("pg_offset", ct.c_uint),
                ("pg_chunk", ct.c_uint),
                ("ts", ct.c_ulonglong),
                ("delta", ct.c_ulonglong),
                ("pid", ct.c_uint),
                ("name", ct.c_char * TASK_COMM_LEN)]


start_ts = 0
prev_ts = 0
delta = 0

# header
print("%-14s %-14s %-6s %-14s %7s" % ("TIME(s)", "COMM", "PID", "PHYSADDR", "LAT(us)"))
def print_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Data)).contents

    global start_ts
    global prev_ts
    global delta

    if start_ts == 0:
        prev_ts = start_ts

    if start_ts == 1:
        delta = float(delta) + (event.ts - prev_ts)

    pysadd=str(event.pg_chunk)+":"+str(event.pg_offset)
    print("%-14.9f %-16s %-6d %-14s %7.2f" % (delta / 1000000, event.name.decode(), 
                  event.pid, pysadd, float(event.delta) / 1000))
    prev_ts = event.ts
    start_ts = 1

# loop with callback to print_event
b["events"].open_perf_buffer(print_event, page_cnt=64)
while 1:
    b.kprobe_poll()
