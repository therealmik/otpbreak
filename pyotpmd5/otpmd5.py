#!/usr/bin/env python3

import numpy
import hashlib
import sys
from cotpmd5 import otpmd5 as digest
import binascii

def tohex(otp):
	return binascii.b2a_hex(tobytes(otp))

def tobytes(otp):
	if sys.byteorder != 'little':
		otp = otp.byteswap()
	return otp.tostring()

def hashbytes(s):
	digest = hashlib.md5(s).digest()
	a = numpy.fromstring(digest, dtype=numpy.uint64)
	if sys.byteorder != 'little':
		a = a.byteswap()
	return numpy.bitwise_xor(*a)

def create(seed, passphrase, sequence):
	s = (seed + passphrase).encode("UTF-8")
	return digest(hashbytes(s), sequence)

