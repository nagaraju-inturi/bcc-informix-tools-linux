#!/usr/bin/python3
#
# fmx_physio_snoop.py  Trace off cpu time for Informix threads
#               For Linux, uses BCC, eBPF. Embedded C.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 9-Mar-2019   Nagaraju Inturi Created this.
#
# USAGE: 
#./ifmx_offcputime_snoop.py
#TIME(s)        COMM           PID    OFFCPUTM(us)
#0.000000000    oninit           14767  990515.68
#0.000064000    oninit           14767   142.28
#1.982759000    oninit           14767  1982701.30

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
    u64 ts;
    u64 delta;
    u32 pid;
    char name[TASK_COMM_LEN];
};

typedef struct ifx_thrtime {
    u64 ts;
} ifx_thrtime_t;
BPF_HASH(bufmap, u64, ifx_thrtime_t);
BPF_PERF_OUTPUT(events);

int do_entry(struct pt_regs *ctx) {
    if (!PT_REGS_PARM2(ctx))
        return 0;

    u64 bp = PT_REGS_FP(ctx);
    ifx_thrtime_t  thrtime = {0};
    u64 paddr = PT_REGS_PARM4(ctx);
    if (!paddr)
         return 0;
    thrtime.ts = bpf_ktime_get_ns();
    bufmap.update(&bp, &thrtime);

    return 0;
}
int do_return(struct pt_regs *ctx)
{
    u64 bp = PT_REGS_FP(ctx);
    ifx_thrtime_t *thrtime = bufmap.lookup(&bp);

    if (thrtime) {
        u64 ts = bpf_ktime_get_ns();
        struct data_t data = {0};
        data.delta = ts - thrtime->ts;
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
funcname="yield_processor_mvp"
b.attach_uprobe(name=oninitpath, sym=funcname, fn_name="do_entry")
b.attach_uretprobe(name=oninitpath, sym=funcname, fn_name="do_return")
funcname2="yield_processor_svp"
b.attach_uprobe(name=oninitpath, sym=funcname2, fn_name="do_entry")
b.attach_uretprobe(name=oninitpath, sym=funcname2, fn_name="do_return")


TASK_COMM_LEN = 16  # linux/sched.h
class Data(ct.Structure):
    _fields_ = [("ts", ct.c_ulonglong),
                ("delta", ct.c_ulonglong),
                ("pid", ct.c_uint),
                ("name", ct.c_char * TASK_COMM_LEN)]


start_ts = 0
prev_ts = 0
delta = 0

# header
print("%-14s %-14s %-6s %7s" % ("TIME(s)", "COMM", "PID", "OFFCPUTM(us)"))
def print_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Data)).contents

    global start_ts
    global prev_ts
    global delta

    if start_ts == 0:
        prev_ts = start_ts

    if start_ts == 1:
        delta = float(delta) + (event.ts - prev_ts)

    print("%-14.9f %-16s %-6d %7.2f" % (delta / 1000000, event.name.decode(), 
                  event.pid, float(event.delta) / 1000))
    prev_ts = event.ts
    start_ts = 1

# loop with callback to print_event
b["events"].open_perf_buffer(print_event, page_cnt=64)
while 1:
    b.kprobe_poll()
