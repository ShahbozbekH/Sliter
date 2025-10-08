#!/usr/bin/python3
from bcc import BPF
import socket
import os
from time import sleep
import sys
from pyroute2 import IPRoute
import struct
import ctypes as ct
from enum import Enum

TASK_COMM_LEN = 1024
SOCKETS = {}

class EventType(Enum):
	CONNECTED = 1
	DATA_RECEIVED = 2
	CLOSED = 3

class Attributes(ct.Structure):
	_fields_ = [
		("eventType", ct.c_int),
		("fd", ct.c_int),
		("bytes", ct.c_int),
		("msg_size", ct.c_int),
	]

class SocketInfo(ct.Structure):
	_fields_ = [
		("attr", Attributes),
		("msg", ct.c_char * 1024),
	]


b = BPF(src_file="sliter.bpf.c")
interface = "lo"


def print_event(cpu, data, size):
	e = ct.cast(data, ct.POINTER(SocketInfo)).contents
	comm = f"e.attr.fd"
	match e.attr.eventType:
		case EventType.CONNECTED.value:
			print(f"Message Connected: {e.msg.decode()}")
			SOCKETS[e.attr.fd] = e
		case EventType.DATA_RECEIVED.value:
			if comm in SOCKETS:
				print(f"msg in Received: {e.msg.decode()}")
		case EventType.CLOSED.value:
			if comm in SOCKETS:
				msgInfo = SOCKETS[e.attr.fd]
				del SOCKETS[e.attr.fd]
				print(f"msg in Closed: {msgInfo.msg.decode()}")
		case _:
			print("Unknown event")

# Capturing http through kprobes
accept = b.get_syscall_fnname("accept4")
read = b.get_syscall_fnname("read")
close = b.get_syscall_fnname("close")

b.attach_kprobe(event=accept, fn_name="http_accept_entry")
b.attach_kprobe(event=read, fn_name="http_read")
b.attach_kprobe(event=close, fn_name="http_close")
b.attach_kretprobe(event=close, fn_name="http_accept_ret")

b["httpOut"].open_perf_buffer(print_event)

# XDP will be the first program hit when a packet is received ingress
fx = b.load_func("xdp", BPF.XDP)
BPF.attach_xdp(interface, fx, 0)

while True:
	try:
		b.perf_buffer_poll()
		sleep(20)
	except KeyboardInterrupt:
		sys.exit(0)

