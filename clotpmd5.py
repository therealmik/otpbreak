#!/usr/bin/python

# Simple python code to launch OpenCL otp-md5 chain calculator
 
import pyopencl as cl
import numpy

DEFAULT_ROUNDS=268435456 # 2 ** 28

def calc_range(start, num, rounds):
	"""Calculate the otp-md5 of the 64-bit numbers range(start, num),
	   with otp sequence of rounds."""

	# Boilerplate OpenCL stuff
	ctx = cl.create_some_context()
	queue = cl.CommandQueue(ctx)
	mf = cl.mem_flags

	# Read the program source and compile
	sourcecode = open("otpmd5.cl").read()
	prg = cl.Program(ctx, sourcecode).build()

	# Create a numpy array of input values, and copy to device
	host_input = numpy.arange(start, start+num, dtype=numpy.uint64)
	dev_input = cl.Buffer(ctx, mf.READ_ONLY | mf.COPY_HOST_PTR, hostbuf=host_input)
	
	# Create a buffer to write the output to
	dev_output = cl.Buffer(ctx, mf.WRITE_ONLY, host_input.nbytes)

	# Execute the kernel, and wait for it to finish
	prg.otpmd5(queue, host_input.shape, None, dev_input, dev_output, numpy.uint32(rounds)).wait()

	# Copy the results from the device
	result = numpy.empty_like(host_input)
	cl.enqueue_copy(queue, result, dev_output).wait()

	# Zip the input with output
	return zip(host_input.byteswap(), result.byteswap())

if __name__ == "__main__":
	import argparse
	parser = argparse.ArgumentParser(description="Calculate chains of OTP-MD5 values")
	parser.add_argument("--start", help="First input OTP value", type=long, default=0L)
	parser.add_argument("--num", help="Number of OTP chains to calculate", type=long, default=1024L)
	parser.add_argument("--rounds", help="Number of rounds in each chain", type=long, default=2**28L)
	args = parser.parse_args()
	for (source, result) in calc_range(args.start, args.num, args.rounds):
		print "%016x %016x" % (source, result)

