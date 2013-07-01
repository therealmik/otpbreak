#include <stdint.h>

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

/*
#define F(x, y, z) (OR(AND(x, y), ANDNOT(z, x)))
#define G(x, y, z) (OR(AND(x, z), ANDNOT(y, z)))
#define H(x, y, z) (XOR(x, XOR(y, z)))
#define I(x, y, z) (XOR(y, ORNOT(x, z)))
*/

#define F(x, y, z) (((x) & (y)) | ((~x) & (z)))
#define G(x, y, z) (((x) & (z)) | ((y) & (~z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define I(x, y, z) ((y) ^ ((x) | (~z)))

/* The normal C way of rotating seems to produce way better
 * CPU code (AVX/SSE) than the rotate() OpenCL function with
 * the Intel CPU ICD.
 *
 * rotate() seemed to pop the individual integers out of the
 * vector, then do rol instructions, leaving it as-is leaves
 * them vectorised, then does the SSE4.x vector shift and or
 * instructions.
 */
// #define ROTATE_LEFT(x, n) ( rotate(x, n) )
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
#define S11 7U
#define S12 12U
#define S13 17U
#define S14 22U
#define S21 5U
#define S22 9U
#define S23 14U
#define S24 20U
#define S31 4U
#define S32 11U
#define S33 16U
#define S34 23U
#define S41 6U
#define S42 10U
#define S43 15U
#define S44 21U

/*
 * Since we are always processing a 64bit value, we can define the entire input
 * buffer except for the first 2 integers as constants
 */
#define X2 0x80U
#define X3 0U
#define X4 0U
#define X5 0U
#define X6 0U
#define X7 0U
#define X8 0U
#define X9 0U
#define X10 0U
#define X11 0U
#define X12 0U
#define X13 0U
#define X14 64U
#define X15 0U

#define otpmd5_round(X0, X1) { \
	unsigned int a = 0x67452301U; \
	unsigned int b = 0xefcdab89U; \
	unsigned int c = 0x98badcfeU; \
	unsigned int d = 0x10325476U; \
	FF(a, b, c, d, X0, S11, 0xd76aa478U); /* 1 */ \
	FF(d, a, b, c, X1, S12, 0xe8c7b756U); /* 2 */ \
	FF(c, d, a, b, X2, S13, 0x242070dbU); /* 3 */ \
	FF(b, c, d, a, X3, S14, 0xc1bdceeeU); /* 4 */ \
	FF(a, b, c, d, X4, S11, 0xf57c0fafU); /* 5 */ \
	FF(d, a, b, c, X5, S12, 0x4787c62aU); /* 6 */ \
	FF(c, d, a, b, X6, S13, 0xa8304613U); /* 7 */ \
	FF(b, c, d, a, X7, S14, 0xfd469501U); /* 8 */ \
	FF(a, b, c, d, X8, S11, 0x698098d8U); /* 9 */ \
	FF(d, a, b, c, X9, S12, 0x8b44f7afU); /* 10 */ \
	FF(c, d, a, b, X10, S13, 0xffff5bb1U); /* 11 */ \
	FF(b, c, d, a, X11, S14, 0x895cd7beU); /* 12 */ \
	FF(a, b, c, d, X12, S11, 0x6b901122U); /* 13 */ \
	FF(d, a, b, c, X13, S12, 0xfd987193U); /* 14 */ \
	FF(c, d, a, b, X14, S13, 0xa679438eU); /* 15 */ \
	FF(b, c, d, a, X15, S14, 0x49b40821U); /* 16 */ \
	GG(a, b, c, d, X1, S21, 0xf61e2562U); /* 17 */ \
	GG(d, a, b, c, X6, S22, 0xc040b340U); /* 18 */ \
	GG(c, d, a, b, X11, S23, 0x265e5a51U); /* 19 */ \
	GG(b, c, d, a, X0, S24, 0xe9b6c7aaU); /* 20 */ \
	GG(a, b, c, d, X5, S21, 0xd62f105dU); /* 21 */ \
	GG(d, a, b, c, X10, S22,  0x2441453U); /* 22 */ \
	GG(c, d, a, b, X15, S23, 0xd8a1e681U); /* 23 */ \
	GG(b, c, d, a, X4, S24, 0xe7d3fbc8U); /* 24 */ \
	GG(a, b, c, d, X9, S21, 0x21e1cde6U); /* 25 */ \
	GG(d, a, b, c, X14, S22, 0xc33707d6U); /* 26 */ \
	GG(c, d, a, b, X3, S23, 0xf4d50d87U); /* 27 */ \
	GG(b, c, d, a, X8, S24, 0x455a14edU); /* 28 */ \
	GG(a, b, c, d, X13, S21, 0xa9e3e905U); /* 29 */ \
	GG(d, a, b, c, X2, S22, 0xfcefa3f8U); /* 30 */ \
	GG(c, d, a, b, X7, S23, 0x676f02d9U); /* 31 */ \
	GG(b, c, d, a, X12, S24, 0x8d2a4c8aU); /* 32 */ \
	HH(a, b, c, d, X5, S31, 0xfffa3942U); /* 33 */ \
	HH(d, a, b, c, X8, S32, 0x8771f681U); /* 34 */ \
	HH(c, d, a, b, X11, S33, 0x6d9d6122U); /* 35 */ \
	HH(b, c, d, a, X14, S34, 0xfde5380cU); /* 36 */ \
	HH(a, b, c, d, X1, S31, 0xa4beea44U); /* 37 */ \
	HH(d, a, b, c, X4, S32, 0x4bdecfa9U); /* 38 */ \
	HH(c, d, a, b, X7, S33, 0xf6bb4b60U); /* 39 */ \
	HH(b, c, d, a, X10, S34, 0xbebfbc70U); /* 40 */ \
	HH(a, b, c, d, X13, S31, 0x289b7ec6U); /* 41 */ \
	HH(d, a, b, c, X0, S32, 0xeaa127faU); /* 42 */ \
	HH(c, d, a, b, X3, S33, 0xd4ef3085U); /* 43 */ \
	HH(b, c, d, a, X6, S34,  0x4881d05U); /* 44 */ \
	HH(a, b, c, d, X9, S31, 0xd9d4d039U); /* 45 */ \
	HH(d, a, b, c, X12, S32, 0xe6db99e5U); /* 46 */ \
	HH(c, d, a, b, X15, S33, 0x1fa27cf8U); /* 47 */ \
	HH(b, c, d, a, X2, S34, 0xc4ac5665U); /* 48 */ \
	II(a, b, c, d, X0, S41, 0xf4292244U); /* 49 */ \
	II(d, a, b, c, X7, S42, 0x432aff97U); /* 50 */ \
	II(c, d, a, b, X14, S43, 0xab9423a7U); /* 51 */ \
	II(b, c, d, a, X5, S44, 0xfc93a039U); /* 52 */ \
	II(a, b, c, d, X12, S41, 0x655b59c3U); /* 53 */ \
	II(d, a, b, c, X3, S42, 0x8f0ccc92U); /* 54 */ \
	II(c, d, a, b, X10, S43, 0xffeff47dU); /* 55 */ \
	II(b, c, d, a, X1, S44, 0x85845dd1U); /* 56 */ \
	II(a, b, c, d, X8, S41, 0x6fa87e4fU); /* 57 */ \
	II(d, a, b, c, X15, S42, 0xfe2ce6e0U); /* 58 */ \
	II(c, d, a, b, X6, S43, 0xa3014314U); /* 59 */ \
	II(b, c, d, a, X13, S44, 0x4e0811a1U); /* 60 */ \
	II(a, b, c, d, X4, S41, 0xf7537e82U); /* 61 */ \
	II(d, a, b, c, X11, S42, 0xbd3af235U); /* 62 */ \
	II(c, d, a, b, X2, S43, 0x2ad7d2bbU); /* 63 */ \
	II(b, c, d, a, X9, S44, 0xeb86d391U); /* 64 */ \
	a += 0x67452301U; \
	b += 0xefcdab89U; \
	c += 0x98badcfeU; \
	d += 0x10325476U; \
	X0 = a ^ c; \
	X1 = b ^ d; \
}

uint64_t _otpmd5(uint64_t* input, int rounds)
{
	uint32_t X0 = ((uint32_t *)input)[0];
	uint32_t X1 = ((uint32_t *)input)[1];

	while(rounds-- > 0)
	{
		otpmd5_round(X0, X1);
	}

	return (uint64_t)((uint64_t)X1) << 32 | ((uint64_t)X0);
}

/* NOTE: Includes round 0 (eg. no hashing) */
void _otpmd5_chain(uint64_t* result, uint64_t* input, int rounds)
{
	uint32_t X0 = ((uint32_t *)&input)[0];
	uint32_t X1 = ((uint32_t *)&input)[1];
	unsigned int i;

	for( i = 0; i < rounds; i++)
	{
		result[i] = (int64_t)((uint64_t)X1) << 32 | ((uint64_t)X0);
		otpmd5_round(X0, X1);
	}
}

