/*
 * This is an OpenSSL-compatible implementation of the RSA Data Security,
 * Inc. MD5 Message-Digest Algorithm.
 *
 * Written by Solar Designer <solar at openwall.com> in 2001, placed in
 * the public domain, and hacked by others.
 */

#if !defined(_MD5_GO_H)
#define _MD5_GO_H

/* Any 32-bit or wider unsigned integer data type will do */
typedef unsigned int MD5_u32plus;
extern void MD5_Go(unsigned char *data, int len, unsigned char *result);

#endif
