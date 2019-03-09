#!/usr/bin/python3
#
# informixlat.py	Informix function latency distribution.
#			For Linux, uses BCC, eBPF. See .c file.
#
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 9-Mar-2019   Nagaraju Inturi Created this.
#
# USAGE: ifmx_func_latency.py funcname [interval [count]]
#
# The default interval is 5 seconds. A Ctrl-C will print the partially
# gathered histogram then exit.
#
#./ifmx_func_latency.py buffget
#Tracing...buffget Hit Ctrl-C to end.
#     usecs               : count     distribution
#         0 -> 1          : 0        |                                        |
#         2 -> 3          : 0        |                                        |
#         4 -> 7          : 54248    |****************************************|
#         8 -> 15         : 990      |                                        |
#        16 -> 31         : 146      |                                        |
#        32 -> 63         : 15       |                                        |


from bcc import BPF
from ctypes import c_ushort, c_int, c_ulonglong
from time import sleep
from sys import argv
import os

def usage():
	print("USAGE: %s funcname [interval [count]]" % argv[0])
	exit()

# arguments
interval = 5
count = -1
funcname="buffget"
if len(argv) > 1:
	funcname = argv[1]
if len(argv) > 2:
	try:
		interval = int(argv[2])
		if interval == 0:
			raise
		if len(argv) > 2:
			count = int(argv[3])
	except:	# also catches -h, --help
		usage()

# load BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>

BPF_HASH(start, u64);
BPF_HISTOGRAM(dist);

int do_entry(struct pt_regs *ctx)
{
        u64 bp,ts;

        bp = PT_REGS_FP(ctx);
        ts = bpf_ktime_get_ns();
        start.update(&bp, &ts);
        return 0;
}
int do_return(struct pt_regs *ctx)
{
        u64 bp, *tsp, delta;

        bp = PT_REGS_FP(ctx);
        tsp = start.lookup(&bp);

        if (tsp != 0) {
                delta = bpf_ktime_get_ns() - *tsp;
                dist.increment(bpf_log2l(delta / 1000));
                start.delete(&bp);
        }

        return 0;
};
"""

oninitpath=str(os.environ.get('INFORMIXDIR'))+"/bin/oninit"
#print(oninitpath)
# load BPF program
b = BPF(text=bpf_text)

b.attach_uprobe(name=oninitpath, sym=funcname, fn_name="do_entry")
b.attach_uretprobe(name=oninitpath, sym=funcname, fn_name="do_return")

# header
print("Tracing..." + funcname + " Hit Ctrl-C to end.")

# output
loop = 0
do_exit = 0
while (1):
	if count > 0:
		loop += 1
		if loop > count:
			exit()
	try:
		sleep(interval)
	except KeyboardInterrupt:
		pass; do_exit = 1

	print
	b["dist"].print_log2_hist("usecs")
	b["dist"].clear()
	if do_exit:
		exit()
