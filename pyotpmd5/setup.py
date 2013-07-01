#!/usr/bin/python3

from distutils.core import setup
from distutils.extension import Extension

try:
	from Cython.Distutils import build_ext
	setup(
	    cmdclass = {'build_ext': build_ext},
	    ext_modules = [Extension("cotpmd5", ["cotpmd5.pyx", "otpmd5.c"])],
	    py_modules = ["otpmd5"],
	)
except ImportError:
	setup(
	    ext_modules = [Extension("cotpmd5", ["cotpmd5.c", "otpmd5.c"])],
	    py_modules = ["otpmd5"],
	)

