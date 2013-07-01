import numpy
cimport numpy

cdef extern from "otpmd5.h":
	ctypedef numpy.int64_t int64_t
	int64_t _otpmd5(int64_t data, int rounds) nogil
	void _otpmd5_chain(int64_t* result, int64_t data, int rounds) nogil

def otpmd5(int64_t data, int rounds):
	cdef int64_t result

	with nogil:
		result = _otpmd5(data, rounds)
	return numpy.int64(result)

def otpmd5_chain(int64_t data, int rounds):
	cdef numpy.ndarray result = numpy.empty(rounds, dtype=numpy.int64)

	with nogil:
		_otpmd5_chain(<int64_t*>result.data, data, rounds)
	return result

