#!/usr/bin/python3

from __future__ import print_function
from bcc import BPF
from ctypes import *
from struct import *
from sys import argv

import sys
import socket
import os
import struct
import binascii
import time


b = BPF(src_file="sliter.bpf.c")
interface = "lo"


# XDP will be the first program hit when a packet is received ingress
fx = b.load_func("xdp", BPF.XDP)
BPF.attach_xdp(interface, fx, 0)

try:
	b.trace_print()
except KeyboardInterrupt:
	sys.exit(0)

