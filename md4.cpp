/*
 * This code implements the MD4 message-digest algorithm.
 * "Just the reference implementation, single stage. Hardly "optimized." Though a good bit faster than libssl's MD4, as it isn't doing nearly the same amount of work." - Bitweasil
 * 
 * little bit optimized (or at least attempted) for NTLM (unicode) by neinbrucke
 */


//#include <cstdlib>
#include <cstring>
#include "md4.h"

/* MD4 Defines as per RFC reference implementation */
#define F(x, y, z) (((x) & (y)) | ((~x) & (z)))
#define G(x, y, z) (((x) & (y)) | ((x) & (z)) | ((y) & (z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32-(n))))
#define FF(a, b, c, d, x, s) { \
    (a) += F ((b), (c), (d)) + (x); \
    (a) = ROTATE_LEFT ((a), (s)); \
  }
#define GG(a, b, c, d, x, s) { \
    (a) += G ((b), (c), (d)) + (x) + (UINT4)0x5a827999; \
    (a) = ROTATE_LEFT ((a), (s)); \
  }
#define HH(a, b, c, d, x, s) { \
    (a) += H ((b), (c), (d)) + (x) + (UINT4)0x6ed9eba1; \
    (a) = ROTATE_LEFT ((a), (s)); \
  }
#define S11 3
#define S12 7
#define S13 11
#define S14 19
#define S21 3
#define S22 5
#define S23 9
#define S24 13
#define S31 3
#define S32 9
#define S33 11
#define S34 15
/* End MD4 Defines */


void MD4_NEW( unsigned char * pData, int length, unsigned char * pDigest)
{
	// For the hash working space
	UINT4 b0,b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11, b12, b13, b14, b15;

	// For the output result
	UINT4 a,b,c,d;

	b0 = 0x00000000;
	b1 = 0x00000000;
	b2 = 0x00000000;
	b3 = 0x00000000;
	b4 = 0x00000000;
	b5 = 0x00000000;
	b6 = 0x00000000;
	b7 = 0x00000000;
	b8 = 0x00000000;
	b9 = 0x00000000;
	b10 = 0x00000000;
	b11 = 0x00000000;
	b12 = 0x00000000;
	b13 = 0x00000000;
	b14 = 0x00000000;
	b15 = 0x00000000; 

	// LOAD DATA INTO b0 ... whatever here.   
	switch (length)
	{
		case 2:
		{
			unsigned char in[4];
			memcpy(in, pData, length);
			in[2] = 0x80;
			in[3] = 0x00;
			UINT4 * pUiIn = (UINT4 *) in;
			b0 = pUiIn[0];
		}
		break;
		case 4:
		{
			unsigned char in[4];
			memcpy(in, pData, length);
			UINT4 * pUiIn = (UINT4 *) in;
			b0 = pUiIn[0];
			b1 = 0x00000080;
		}
		break;
		case 6:
		{
			unsigned char in[8];
			memcpy(in, pData, length);
			in[6] = 0x80;
			in[7] = 0x00;
			UINT4 * pUiIn = (UINT4 *) in;
			b0 = pUiIn[0];
			b1 = pUiIn[1];
		}
		break;
		case 8:
		{
			unsigned char in[8];
			memcpy(in, pData, length);
			UINT4 * pUiIn = (UINT4 *) in;
			b0 = pUiIn[0];
			b1 = pUiIn[1];
			b2 = 0x00000080;
		}
		break;
		case 10:
		{
			unsigned char in[12];
			memcpy(in, pData, length);
			in[10] = 0x80;
			in[11] = 0x00;
			UINT4 * pUiIn = (UINT4 *) in;
			b0 = pUiIn[0];
			b1 = pUiIn[1];
			b2 = pUiIn[2];
		}
		break;
		default:
		{
			unsigned char in[32];
			memcpy(in, pData, length);
			in[length] = 0x80;
			memset(in + length + 1, 0, 32 - length - 1);
			UINT4 * pUiIn = (UINT4 *) in;
			b0 = pUiIn[0];
			b1 = pUiIn[1];
			b2 = pUiIn[2];
			b3 = pUiIn[3];
			b4 = pUiIn[4];
			b5 = pUiIn[5];
			b6 = pUiIn[6];
			b7 = pUiIn[7]; // max 14 2byte chars (ntlm)
			b8 = pUiIn[8];
		}
		break;
	}

	b14 = length << 3;

	a = 0x67452301;
	b = 0xefcdab89;
	c = 0x98badcfe;
	d = 0x10325476;

	/* Round 1 */
	FF (a, b, c, d, b0, S11); /* 1 */
	FF (d, a, b, c, b1, S12); /* 2 */
	FF (c, d, a, b, b2, S13); /* 3 */
	FF (b, c, d, a, b3, S14); /* 4 */
	FF (a, b, c, d, b4, S11); /* 5 */
	FF (d, a, b, c, b5, S12); /* 6 */
	FF (c, d, a, b, b6, S13); /* 7 */
	FF (b, c, d, a, b7, S14); /* 8 */
	FF (a, b, c, d, 0, S11); /* 9 */
	FF (d, a, b, c, 0, S12); /* 10 */
	FF (c, d, a, b, 0, S13); /* 11 */
	FF (b, c, d, a, 0, S14); /* 12 */
	FF (a, b, c, d, 0, S11); /* 13 */
	FF (d, a, b, c, 0, S12); /* 14 */
	FF (c, d, a, b, b14, S13); /* 15 */
	FF (b, c, d, a, 0, S14); /* 16 */

	/* Round 2 */
	GG (a, b, c, d, b0, S21); /* 17 */
	GG (d, a, b, c, b4, S22); /* 18 */
	GG (c, d, a, b, 0, S23); /* 19 */
	GG (b, c, d, a, 0, S24); /* 20 */
	GG (a, b, c, d, b1, S21); /* 21 */
	GG (d, a, b, c, b5, S22); /* 22 */
	GG (c, d, a, b, 0, S23); /* 23 */
	GG (b, c, d, a, 0, S24); /* 24 */
	GG (a, b, c, d, b2, S21); /* 25 */
	GG (d, a, b, c, b6, S22); /* 26 */
	GG (c, d, a, b, 0, S23); /* 27 */
	GG (b, c, d, a, b14, S24); /* 28 */
	GG (a, b, c, d, b3, S21); /* 29 */
	GG (d, a, b, c, b7, S22); /* 30 */
	GG (c, d, a, b, 0, S23); /* 31 */
	GG (b, c, d, a, 0, S24); /* 32 */

	/* Round 3 */
	HH (a, b, c, d, b0, S31); /* 33 */
	HH (d, a, b, c, 0, S32); /* 34 */
	HH (c, d, a, b, b4, S33); /* 35 */
	HH (b, c, d, a, 0, S34); /* 36 */
	HH (a, b, c, d, b2, S31); /* 37 */
	HH (d, a, b, c, 0, S32); /* 38 */
	HH (c, d, a, b, b6, S33); /* 39 */
	HH (b, c, d, a, b14, S34); /* 40 */
	HH (a, b, c, d, b1, S31); /* 41 */
	HH (d, a, b, c, 0, S32); /* 42 */
	HH (c, d, a, b, b5, S33); /* 43 */
	HH (b, c, d, a, 0, S34); /* 44 */
	HH (a, b, c, d, b3, S31); /* 45 */
	HH (d, a, b, c, 0, S32); /* 46 */
	HH (c, d, a, b, b7, S33); /* 47 */
	HH (b, c, d, a, 0, S34); /* 48 */

	// Finally, add initial values, as this is the only pass we make.
	a += 0x67452301;
	b += 0xefcdab89;
	c += 0x98badcfe;
	d += 0x10325476;

	UINT4 buf[4] = { a, b, c, d};
	memcpy(pDigest, buf, 16);

	return;
}
