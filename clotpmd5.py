#!/usr/bin/python

# Simple python code to launch OpenCL otp-md5 chain calculator

import pyopencl as cl
import numpy

def calc_range(start, num, rounds, per_exec_rounds=None):
	"""Calculate the otp-md5 of the 64-bit numbers range(start, num),
	   with otp sequence of rounds."""

	if per_exec_rounds is None:
		per_exec_rounds = rounds

	if rounds % per_exec_rounds != 0:
		raise ValueError("rounds must be a multiple of perexec")

	# Boilerplate OpenCL stuff
	ctx = cl.create_some_context()
	queue = cl.CommandQueue(ctx)
	mf = cl.mem_flags

	# Read the program source and compile
	sourcecode = open("otpmd5.cl").read()
	prg = cl.Program(ctx, sourcecode).build()

	# Create a numpy array of input values, and copy to device
	host_input = numpy.arange(start, start+num, dtype=numpy.uint64)
	dev_data = cl.Buffer(ctx, mf.READ_WRITE | mf.COPY_HOST_PTR, hostbuf=host_input)
	
	# Execute the kernel, and wait for it to finish
	for i in xrange(rounds / per_exec_rounds):
		prg.otpmd5(queue, host_input.shape, None, dev_data, numpy.uint32(per_exec_rounds)).wait()

	# Copy the results from the device
	result = numpy.empty_like(host_input)
	cl.enqueue_copy(queue, result, dev_data).wait()

	# Zip the input with output
	return zip(host_input.byteswap(), result.byteswap())

if __name__ == "__main__":
	import argparse
	parser = argparse.ArgumentParser(description="Calculate chains of OTP-MD5 values")
	parser.add_argument("--start", help="First input OTP value", type=long, default=0L)
	parser.add_argument("--num", help="Number of OTP chains to calculate", type=long, default=1024L)
	parser.add_argument("--rounds", help="Number of rounds in each chain", type=long, default=2**28L)
	parser.add_argument("--perexec", help="Number of rounds per-execution", type=long)

	args = parser.parse_args()
	for (source, result) in calc_range(args.start, args.num, args.rounds, args.perexec):
		print "%016x %016x" % (source, result)

