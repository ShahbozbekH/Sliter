#!/usr/bin/python3
from bcc import BPF
import socket
import os
from time import sleep
import sys
from pyroute2 import IPRoute

b = BPF(src_file="sliter.bpf.c")
interface = "lo"


# Capturing http through kprobes
accept = b.get_syscall_fnname("accept4")
read = b.get_syscall_fnname("read")
close = b.get_syscall_fnname("close")

b.attach_kprobe(event=accept, fn_name="http_accept")
b.attach_kprobe(event=read, fn_name="http_read")
b.attach_kprobe(event=close, fn_name="http_close")

# XDP will be the first program hit when a packet is received ingress
fx = b.load_func("xdp", BPF.XDP)
BPF.attach_xdp(interface, fx, 0)


try:
    b.trace_print()
except KeyboardInterrupt:
    sys.exit(0)

