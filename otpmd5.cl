/*
 **********************************************************************
 ** OpenCL implementation written by Michael Samuel <mik@miknet.net> **
 **								     **
 ** No further restrictions apply over RSA License.		     **
 **********************************************************************
 */

/* This kernel attempts to optimise MD5 for calculating potentially long chains of folded
 * otp-md5.
 *
 * The folding mechanism defined for 128bit hashes is simply to return a ^ c, b ^ d
 *
 * The optimisations made by mik:
 * - Create a loop.  This busys out both ATI and NVIDIA cards, so don't run this kernel on
 *   a card that you're using as a display (if you want to get any work done this week)
 * - As all input is exactly 64 bits, there's no need to maintain a buffer, or write implement
 *   MD5_Update.  Instead, all but the first 64 bits of the buffer are implemented as defines,
 *   which are compiled into constants.  X0 and X1 (the first 8 bytes of the buffer) are
 *   integers grabbed from the input buffer
 * - At various points, I fudged with the order of operations, using builtin functions etc,
 *   all of which is pointless now that compilers have improved.
 * - Using the builting rotate function in-fact makes the CPU code worse.  I'm assuing since
 *   the GPU OpenCL implementations use LLVM too, that it's the same with them.
 */

/*
 **********************************************************************
 ** Copyright (C) 1990, RSA Data Security, Inc. All rights reserved. **
 **								     **
 ** License to copy and use this software is granted provided that   **
 ** it is identified as the "RSA Data Security, Inc. MD5 Message     **
 ** Digest Algorithm" in all material mentioning or referencing this **
 ** software or this function.					     **
 **								     **
 ** License is also granted to make and use derivative works	     **
 ** provided that such works are identified as "derived from the RSA **
 ** Data Security, Inc. MD5 Message Digest Algorithm" in all	     **
 ** material mentioning or referencing the derived work.	     **
 **								     **
 ** RSA Data Security, Inc. makes no representations concerning      **
 ** either the merchantability of this software or the suitability   **
 ** of this software for any particular purpose.  It is provided "as **
 ** is" without express or implied warranty of any kind.	     **
 **								     **
 ** These notices must be retained in any copies of any part of this **
 ** documentation and/or software.				     **
 **********************************************************************
 */

/* F, G and H are basic MD5 functions: selection, majority, parity
 *
 * This way of defining them used to help the compilers when AVX was
 * new.  As of Jan2013 it produces the same ASM as the original with
 * all compilers I've tried.  The macros are arguably easier to read
 * so I've left them there.  The original F,G,H,I functions are left
 * commented out below.
 */
#define OR(a, b) (a | b)
#define ORNOT(a, b) (a | (~b))
#define XOR(a, b) (a ^ b)
#define AND(a, b) (a & b)
#define ANDNOT(a, b) (a & (~b))

#define F(x, y, z) (OR(AND(x, y), ANDNOT(z, x)))
#define G(x, y, z) (OR(AND(x, z), ANDNOT(y, z)))
#define H(x, y, z) (XOR(x, XOR(y, z)))
#define I(x, y, z) (XOR(y, ORNOT(x, z)))

/*
#define F(x, y, z) (((x) & (y)) | ((~x) & (z)))
#define G(x, y, z) (((x) & (z)) | ((y) & (~z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define I(x, y, z) ((y) ^ ((x) | (~z)))
*/

/* The normal C way of rotating seems to produce way better
 * CPU code (AVX/SSE) than the rotate() OpenCL function with
 * the Intel CPU ICD.
 *
 * rotate() seemed to pop the individual integers out of the
 * vector, then do rol instructions, leaving it as-is leaves
 * them vectorised, then does the SSE4.x vector shift and or
 * instructions.
 */
#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32-(n))))

/* FF, GG, HH, and II transformations for rounds 1, 2, 3, and 4 */
/* Rotation is separate from addition to prevent recomputation */
#define FF(a, b, c, d, x, s, ac) \
  {(a) += F((b), (c), (d)) + (x) + (ac); \
   (a) = ROTATE_LEFT((a), (s)); \
   (a) += (b); \
  }
#define GG(a, b, c, d, x, s, ac) \
  {(a) += G((b), (c), (d)) + (x) + (ac); \
   (a) = ROTATE_LEFT((a), (s)); \
   (a) += (b); \
  }
#define HH(a, b, c, d, x, s, ac) \
  {(a) += H((b), (c), (d)) + (x) + (ac); \
   (a) = ROTATE_LEFT((a), (s)); \
   (a) += (b); \
  }
#define II(a, b, c, d, x, s, ac) \
  {(a) += I((b), (c), (d)) + (x) + (ac); \
   (a) = ROTATE_LEFT((a), (s)); \
   (a) += (b); \
  }

/*
 * S values are the amount to rotate left by in each round
 * Each round uses 4 different shift values, 1 per step
 */
#define S11 7
#define S12 12
#define S13 17
#define S14 22
#define S21 5
#define S22 9
#define S23 14
#define S24 20
#define S31 4
#define S32 11
#define S33 16
#define S34 23
#define S41 6
#define S42 10
#define S43 15
#define S44 21

/*
 * Since we are always processing a 64bit value, we can define the entire input
 * buffer except for the first 2 integers as constants
 */
#define X2 0x80
#define X3 0
#define X4 0
#define X5 0
#define X6 0
#define X7 0
#define X8 0
#define X9 0
#define X10 0
#define X11 0
#define X12 0
#define X13 0
#define X14 64
#define X15 0

#define otpmd5_round(X0, X1) { \
	uint a = 0x67452301; \
	uint b = 0xefcdab89; \
	uint c = 0x98badcfe; \
	uint d = 0x10325476; \
	FF(a, b, c, d, X0, S11, 0xd76aa478); /* 1 */ \
	FF(d, a, b, c, X1, S12, 0xe8c7b756); /* 2 */ \
	FF(c, d, a, b, X2, S13, 0x242070db); /* 3 */ \
	FF(b, c, d, a, X3, S14, 0xc1bdceee); /* 4 */ \
	FF(a, b, c, d, X4, S11, 0xf57c0faf); /* 5 */ \
	FF(d, a, b, c, X5, S12, 0x4787c62a); /* 6 */ \
	FF(c, d, a, b, X6, S13, 0xa8304613); /* 7 */ \
	FF(b, c, d, a, X7, S14, 0xfd469501); /* 8 */ \
	FF(a, b, c, d, X8, S11, 0x698098d8); /* 9 */ \
	FF(d, a, b, c, X9, S12, 0x8b44f7af); /* 10 */ \
	FF(c, d, a, b, X10, S13, 0xffff5bb1); /* 11 */ \
	FF(b, c, d, a, X11, S14, 0x895cd7be); /* 12 */ \
	FF(a, b, c, d, X12, S11, 0x6b901122); /* 13 */ \
	FF(d, a, b, c, X13, S12, 0xfd987193); /* 14 */ \
	FF(c, d, a, b, X14, S13, 0xa679438e); /* 15 */ \
	FF(b, c, d, a, X15, S14, 0x49b40821); /* 16 */ \
	GG(a, b, c, d, X1, S21, 0xf61e2562); /* 17 */ \
	GG(d, a, b, c, X6, S22, 0xc040b340); /* 18 */ \
	GG(c, d, a, b, X11, S23, 0x265e5a51); /* 19 */ \
	GG(b, c, d, a, X0, S24, 0xe9b6c7aa); /* 20 */ \
	GG(a, b, c, d, X5, S21, 0xd62f105d); /* 21 */ \
	GG(d, a, b, c, X10, S22,  0x2441453); /* 22 */ \
	GG(c, d, a, b, X15, S23, 0xd8a1e681); /* 23 */ \
	GG(b, c, d, a, X4, S24, 0xe7d3fbc8); /* 24 */ \
	GG(a, b, c, d, X9, S21, 0x21e1cde6); /* 25 */ \
	GG(d, a, b, c, X14, S22, 0xc33707d6); /* 26 */ \
	GG(c, d, a, b, X3, S23, 0xf4d50d87); /* 27 */ \
	GG(b, c, d, a, X8, S24, 0x455a14ed); /* 28 */ \
	GG(a, b, c, d, X13, S21, 0xa9e3e905); /* 29 */ \
	GG(d, a, b, c, X2, S22, 0xfcefa3f8); /* 30 */ \
	GG(c, d, a, b, X7, S23, 0x676f02d9); /* 31 */ \
	GG(b, c, d, a, X12, S24, 0x8d2a4c8a); /* 32 */ \
	HH(a, b, c, d, X5, S31, 0xfffa3942); /* 33 */ \
	HH(d, a, b, c, X8, S32, 0x8771f681); /* 34 */ \
	HH(c, d, a, b, X11, S33, 0x6d9d6122); /* 35 */ \
	HH(b, c, d, a, X14, S34, 0xfde5380c); /* 36 */ \
	HH(a, b, c, d, X1, S31, 0xa4beea44); /* 37 */ \
	HH(d, a, b, c, X4, S32, 0x4bdecfa9); /* 38 */ \
	HH(c, d, a, b, X7, S33, 0xf6bb4b60); /* 39 */ \
	HH(b, c, d, a, X10, S34, 0xbebfbc70); /* 40 */ \
	HH(a, b, c, d, X13, S31, 0x289b7ec6); /* 41 */ \
	HH(d, a, b, c, X0, S32, 0xeaa127fa); /* 42 */ \
	HH(c, d, a, b, X3, S33, 0xd4ef3085); /* 43 */ \
	HH(b, c, d, a, X6, S34,  0x4881d05); /* 44 */ \
	HH(a, b, c, d, X9, S31, 0xd9d4d039); /* 45 */ \
	HH(d, a, b, c, X12, S32, 0xe6db99e5); /* 46 */ \
	HH(c, d, a, b, X15, S33, 0x1fa27cf8); /* 47 */ \
	HH(b, c, d, a, X2, S34, 0xc4ac5665); /* 48 */ \
	II(a, b, c, d, X0, S41, 0xf4292244); /* 49 */ \
	II(d, a, b, c, X7, S42, 0x432aff97); /* 50 */ \
	II(c, d, a, b, X14, S43, 0xab9423a7); /* 51 */ \
	II(b, c, d, a, X5, S44, 0xfc93a039); /* 52 */ \
	II(a, b, c, d, X12, S41, 0x655b59c3); /* 53 */ \
	II(d, a, b, c, X3, S42, 0x8f0ccc92); /* 54 */ \
	II(c, d, a, b, X10, S43, 0xffeff47d); /* 55 */ \
	II(b, c, d, a, X1, S44, 0x85845dd1); /* 56 */ \
	II(a, b, c, d, X8, S41, 0x6fa87e4f); /* 57 */ \
	II(d, a, b, c, X15, S42, 0xfe2ce6e0); /* 58 */ \
	II(c, d, a, b, X6, S43, 0xa3014314); /* 59 */ \
	II(b, c, d, a, X13, S44, 0x4e0811a1); /* 60 */ \
	II(a, b, c, d, X4, S41, 0xf7537e82); /* 61 */ \
	II(d, a, b, c, X11, S42, 0xbd3af235); /* 62 */ \
	II(c, d, a, b, X2, S43, 0x2ad7d2bb); /* 63 */ \
	II(b, c, d, a, X9, S44, 0xeb86d391); /* 64 */ \
	a += 0x67452301; \
	b += 0xefcdab89; \
	c += 0x98badcfe; \
	d += 0x10325476; \
	X0 = a ^ c; \
	X1 = b ^ d; \
}

/* grab input from @data, run @rounds otpmd5 operations, write output back to @data */
__kernel void get_otpmd5_result(__global uint* data, uint rounds)
{
	size_t OFFSET = get_global_id(0) * 2;
	uint X0 = data[OFFSET];
	uint X1 = data[OFFSET+1];

	while(rounds-- > 0)
		otpmd5_round(X0, X1);

	data[OFFSET] = X0;
	data[OFFSET+1] = X1;
}

/* grab input from @input, run @rounds otpmd5 operations, output to @output
 * note that each 'column' is the output of a thread, and each 'row' is the
 * next otpmd5 round */
__kernel void get_otpmd5_chain(__global uint2* input, __global uint2* output, uint rounds)
{
	size_t global_id = get_global_id(0);
	size_t global_size = get_global_size(0);

	uint2 data = input[global_id];

	for(uint i = 0; i < rounds; i++)
	{
		otpmd5_round(data.x, data.y);
		output[(global_size*i)+global_id] = data;
	}
}

/* grab input from @data, run @rounds otpmd5 operations, write output back to @data */
__kernel void get_otpmd5_64k_rounds(__global uint* data)
{
	size_t OFFSET = get_global_id(0) * 2;
	uint X0 = data[OFFSET];
	uint X1 = data[OFFSET+1];

	for(uint i = 0; i < 65536; i++)
		otpmd5_round(X0, X1);

	data[OFFSET] = X0;
	data[OFFSET+1] = X1;
}

