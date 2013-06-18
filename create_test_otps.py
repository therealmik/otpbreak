#!/usr/bin/python3

import random
import string
import hashlib
import struct
import pyopencl as cl
import numpy
import os.path
import pickle
import otpmd5

#def otp_md5(string, n=0):
#	"""Perform basic otp_md5 of string, creating sequence n"""
#	for i in range(n+1):
#		digest = hashlib.md5(string).digest()
#		asInts = struct.unpack('>4i', digest)
#		string = struct.pack('>ii', asInts[0] ^ asInts[2], asInts[1] ^ asInts[3])
#	return string
#	
#def otp_md5_numpy(o, n=0):
#	if isinstance(o, str):
#		s = o.encode("utf-8")
#	elif isinstance(o, bytes):
#		s = o
#	else:
#		s = o.tostring()
#	result = otp_md5(s, n)
#	return numpy.fromstring(result, dtype=numpy.uint64)[0]

passchars = string.ascii_letters + string.digits
class random_otp():
	"""Generate a random OTP"""

	def __init__(self):
		self.sequence = 50;
		self.seed = "{0:s}{1:s}{2:05d}".format(
			random.choice(string.ascii_lowercase),
			random.choice(string.ascii_lowercase),
			random.randint(0, 99999))
		self.password = "".join([ random.choice(passchars) for _ in range(16) ])
		self.otp = otpmd5.create(self.seed, self.password, self.sequence)
		self.breaks = []

	def __repr__(self):
		return "random_otp(seed={0:s}, seq={1:d}, pass={2:s}, otp={3:s})".format(self.seed, self.sequence, self.password, otpmd5.tohex(self.otp))

	def save(self):
		filename = "otpmd5_{0:s}_{1:d}_{2:s}_candidates".format(self.seed, self.sequence, self.password)
		with open(filename, "w") as fd:
			for rounds, source in self.breaks:
				fd.write(str(rounds) + "\t" + otpmd5.tohex(source) + "\n")

def find_breaks(table, base_round, otp, results):
	for i in range(len(results)):
		result = results[i]
		roundnum = base_round + i
		for source in table.get(result):
			otp.breaks.append((roundnum, source))
			print("Found conflict: {0:s}, roundnum={1:d}, source={2:s}, break={3:s}".format(repr(otp), roundnum, otpmd5.tohex(source), otpmd5.tohex(result)))

def process_otps(otplist, rounds, batch):
	"""Process the list of otps, hashing themselves for @rounds, yielding every @batch rounds"""

	# Boilerplate OpenCL
	ctx = cl.create_some_context()
	queue = cl.CommandQueue(ctx)
	mf = cl.mem_flags

	# Read and build kernel
	with open("otpmd5_break.cl", "r") as fd:
		prg = cl.Program(ctx, fd.read())
	prg.build()

	# Create numpy array of 64bit integers containing the otps we want to break
	host_input = numpy.asarray([o.otp for o in otplist])
	# Copy that buffer to the device. Use read-write buffer so we can continue easily
	dev_input = cl.Buffer(ctx, mf.READ_WRITE | mf.COPY_HOST_PTR, hostbuf=host_input)
	dev_output = cl.Buffer(ctx, mf.WRITE_ONLY, batch * len(otplist) * 8)

	host_output = host_input.transpose() # So we yield the original OTPs for breaking
	host_output.shape = (1, len(otplist))

	roundnum = 0 # Round 0 = no hashes
	while roundnum <= rounds:
		evt = prg.otpmd5_break(queue, host_input.shape, None, dev_input, dev_output, numpy.uint32(batch))
		yield (roundnum, zip(otplist, host_output.transpose()))
		roundnum += host_output.shape[0]
		host_output = numpy.empty((batch, len(otplist)), dtype=numpy.uint64)
		cl.enqueue_copy(queue, host_output, dev_output).wait()
	yield (roundnum, zip(otplist, host_output.transpose()))

class otptable(object):
	"""A hashtable that's hopefully more efficient for this than python dict"""
	def __init__(self, bits=21):
		self.mask = ~(numpy.uint64(-1) << numpy.uint32(bits))
		self.table = [ None for _ in range(2**bits) ]

	def put(self, datum):
		index = datum[0,1] & self.mask
		if self.table[index] is None:
			self.table[index] = datum
		else:
			self.table[index] = numpy.array(
				numpy.concatenate([self.table[index], datum]),
				copy=True)

	def get(self, key):
		index = key & self.mask
		if self.table[index] is None:
			return []
		else:
			return [ x[0] for x in self.table[index] if x[1] == key ]

	@classmethod
	def parse_blocks(cls, filename):
		d = cls()
		with open(filename, "r") as fd:
			for line in fd:
				datum = numpy.fromstring(
					bytes.fromhex(line.strip()),
					dtype=numpy.uint64)
				datum.shape=1,2
				d.put(datum)
		return d

def validate_results(otp, base_round, results):
	"""Call this instead of find_breaks to compare host version to GPU version"""
	o = otp.otp.digest(base_round)
	for i in range(len(results)):
		print(otpmd5.tohex(results[i]), otpmd5.tohex(o))
		o = otpmd5.digest(o)
	
if __name__ == "__main__":
	import argparse
	parser = argparse.ArgumentParser(description="Calculate random OTP-MD5 tests")
	parser.add_argument("--rounds", help="Number of rounds in each OTP chain", type=int, default=2**28)
	parser.add_argument("--batch", help="Number of OTPs to batch at a time", type=int, default=2**16)
	parser.add_argument("--num", help="Number of test OTPs to create at a time", type=int, default=64)
	parser.add_argument("--filename", help="File containing OTP blocks", required=True)
	args = parser.parse_args()

	otplist = [random_otp() for _ in range(args.num)]
	table = otptable.parse_blocks(args.filename)
	print("Table load complete")

	for (base_round, otp_and_results) in process_otps(otplist, args.rounds, args.batch):
		for (otp, results) in otp_and_results:
			find_breaks(table, base_round, otp, results)
			#validate_results(otp, base_round, results)
		print("Completed rounds {0:d} - {1:d}".format(base_round, base_round + len(results)))

	for o in otplist:
		o.save()

