#!/usr/bin/env python3

import numpy
import hashlib
import sys

def tohex(otp):
	return "{0:016x}".format(otp.byteswap())

def tobytes_portable(otp):
	return bytes.fromhex(tohex(otp))
	
if sys.byteorder == 'little':
	tobytes = numpy.uint64.tostring
else:
	tobytes = tobytes_portable

def hashbytes(s):
	digest = hashlib.md5(s).digest()
	return numpy.bitwise_xor(*numpy.fromstring(digest, dtype=numpy.uint64))

def create(seed, passphrase, sequence):
	s = (seed + passphrase).encode("UTF-8")
	return digest(hashbytes(s), sequence)

def digest(otp, sequence=1):
	for _ in range(sequence):
		otp = hashbytes(tobytes(otp))
	return otp

