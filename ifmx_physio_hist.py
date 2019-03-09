#!/usr/bin/python3

#
# ifmx_physio_hist.py  Histogram of Informix page count request for disk io
#
# Runs until ctrl-c is pressed.
#
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 9-Mar-2019   Nagaraju Inturi Created this.
#

from __future__ import print_function
import bcc
import time
import os

text = """
#include <uapi/linux/ptrace.h>
BPF_HISTOGRAM(dist);
int count(struct pt_regs *ctx) {
    dist.increment(bpf_log2l(PT_REGS_PARM5(ctx)));
    return 0;
}
"""

b = bcc.BPF(text=text)
oninitpath=str(os.environ.get('INFORMIXDIR'))+"/bin/oninit"
sym="physio"
b.attach_uprobe(name=oninitpath, sym=sym, fn_name="count")


dist = b["dist"]

try:
    while True:
        time.sleep(1)
        print("%-8s\n" % time.strftime("%H:%M:%S"), end="")
        dist.print_log2_hist(sym + " Disk IO page count:")
        dist.clear()

except KeyboardInterrupt:
    pass
