#!/usr/bin/python3

import string
import hashlib
import random
import otpmd5
import random
import cotpmd5
import sqlite3
import numpy

sqlite3.register_adapter(numpy.int64, int)

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

def find_breaks(db, rounds, otp):
	print("Finding breaks for " + repr(otp))

	for (roundnum, value) in enumerate(cotpmd5.otpmd5_chain(otp.otp, rounds)):
		cur = db.cursor()
		cur.execute("SELECT source FROM otpmd5 WHERE result = %s", [int(numpy.int64(value))])
		for row in cur:
			source = numpy.uint64(row[0])
			otp.breaks.append((roundnum, source))
			print("Found candidate: {0:s}, roundnum={1:d}, source={2:s}, break={3:s}".format(repr(otp), roundnum, otpmd5.tohex(source), otpmd5.tohex(value)))
			sec_cur = db.cursor()
			sec_cur.execute("SELECT source FROM otpmd5_conflicts WHERE result = %s", [int(numpy.int64(value))])
			for row in sec_cur:
				source = numpy.uint64(row[0])
				otp.breaks.append((roundnum, source))
				print("Found candidate: {0:s}, roundnum={1:d}, source={2:s}, break={3:s}".format(repr(otp), roundnum, otpmd5.tohex(source), otpmd5.tohex(value)))

def validate_breaks(otp, rounds):
	for (roundnum, source) in otp.breaks:
		result = cotpmd5.otpmd5_chain(source, rounds)
		print("{0:s} + {1:-6d} = {2:s} : {3:s}".format(otpmd5.tohex(source), 65535-roundnum, otpmd5.tohex(result[65535-roundnum]), otpmd5.tohex(otp.otp)))
		if otp.otp in result:
			print("Break found for {0:s}: {1:s}".format(repr(otp), otpmd5.tohex(source)))
			return True
	return False
	
if __name__ == "__main__":
	import argparse
	parser = argparse.ArgumentParser(description="Calculate random OTP-MD5 tests")
	parser.add_argument("--rounds", help="Number of rounds in each OTP chain", type=int, default=2**16)
	parser.add_argument("--database", help="Database containing OTP blocks", required=True)
	args = parser.parse_args()

	#db = sqlite3.connect(args.database, isolation_level=None)
	import psycopg2
	db = psycopg2.connect(args.database)

	while True:
		otp = random_otp()
		find_breaks(db, args.rounds, otp)
		if validate_breaks(otp, args.rounds):
			break

