#!/usr/bin/python3
#
# buffget_count  Trace buffget() and print a frequency count of strings.
#               For Linux, uses BCC, eBPF. Embedded C.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 9-Mar-2019   Nagaraju Inturi Created this.
#
#./ifmx_buffget_count.py
#Tracing buffget()... Hit Ctrl-C to end.
#  PHYSADDR COUNT
#7:676          1
#7:1500         1
#7:804          1
#7:692          1

from __future__ import print_function
from bcc import BPF
from time import sleep
import os

# load BPF program
b = BPF(text="""
#include <uapi/linux/ptrace.h>

struct key_t {
    u64 paddr;
};
BPF_HASH(counts, struct key_t);

int count(struct pt_regs *ctx) {
    if (!PT_REGS_PARM2(ctx))
        return 0;

    struct key_t key = {};
    u64 zero = 0, *val;

    key.paddr = PT_REGS_PARM2(ctx);
     if (key.paddr == 0)
         return 0;
    val = counts.lookup_or_init(&key, &zero);
    (*val)++;
    return 0;
};
""")
oninitpath=str(os.environ.get('INFORMIXDIR'))+"/bin/oninit"
b.attach_uprobe(name=oninitpath, sym="buffget", fn_name="count")

# header
print("Tracing buffget()... Hit Ctrl-C to end.")

# sleep until Ctrl-C
try:
    sleep(99999999)
except KeyboardInterrupt:
    pass

# print output
print("%10s %s" % ("PHYSADDR", "COUNT"))
counts = b.get_table("counts")
for k, v in sorted(counts.items(), key=lambda counts: counts[1].value):
    offset = k.paddr & 0xFFFFFFFF
    chunk = k.paddr  >> 32
    print("%d:%d %10d" % (chunk, offset, v.value))
