import numpy
cimport numpy

cdef extern from "otpmd5.h":
	ctypedef numpy.uint64_t uint64_t
	uint64_t _otpmd5(uint64_t* start, int rounds) nogil
	void _otpmd5_chain(uint64_t* result, uint64_t* start, int rounds) nogil

def otpmd5(uint64_t start, int rounds):
	cdef uint64_t result

	with nogil:
		result = _otpmd5(&start, rounds)
	return numpy.uint64(result)

def otpmd5_chain(uint64_t start, int rounds):
	cdef numpy.ndarray result = numpy.empty(rounds, dtype=numpy.uint64)

	with nogil:
		_otpmd5_chain(<uint64_t*>result.data, &start, rounds)
	return result


