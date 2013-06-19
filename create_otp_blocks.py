#!/usr/bin/python

# Simple python code to launch OpenCL otp-md5 chain calculator

import pyopencl as cl
import numpy
import sqlite3
import binascii
import sys

def to_hex(item):
	return binascii.b2a_hex(item.tostring())

def send_output(host_input, result):
	for r in ( (to_hex(i), to_hex(r)) for (i, r) in zip(host_input, result)):
		sys.stdout.write(",".join(r) + "\n")

def calc_range(start, num, perexec):
	"""Calculate the otp-md5 of the 64-bit numbers range(start, num),
	   with otp sequence of rounds."""

	assert(num % perexec == 0)

	# Boilerplate OpenCL stuff
	ctx = cl.create_some_context()
	queue = cl.CommandQueue(ctx)
	mf = cl.mem_flags

	# Read the program source and compile
	sourcecode = open("otpmd5.cl").read()
	prg = cl.Program(ctx, sourcecode).build()

	for i in xrange(num / perexec):
		offset = start + (perexec * i)

		host_input = numpy.arange(offset, offset+perexec, dtype=numpy.uint64)
		result = numpy.empty_like(host_input)
		dev_input = cl.Buffer(ctx, mf.READ_ONLY | mf.USE_HOST_PTR, hostbuf=host_input)
		dev_output = cl.Buffer(ctx, mf.READ_WRITE, size=result.size * result.itemsize)
		prg.get_otpmd5_64k_rounds(queue, host_input.shape, None, dev_input, dev_output).wait()
		cl.enqueue_copy(queue, result, dev_output).wait()
		send_output(host_input, result)

if __name__ == "__main__":
	import argparse
	parser = argparse.ArgumentParser(description="Calculate chains of OTP-MD5 values")
	parser.add_argument("--start", help="First input OTP value", type=long, default=0L)
	parser.add_argument("--num", help="Number of OTP chains to calculate", type=long, default=2147483648L)
	parser.add_argument("--perexec", help="Number of chains per-execution", type=long, default=65536L)

	args = parser.parse_args()
	calc_range(args.start, args.num, args.perexec)

