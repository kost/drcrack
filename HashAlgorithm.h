/*
   RainbowCrack - a general propose implementation of Philippe Oechslin's faster time-memory trade-off technique.

   Copyright (C) Zhu Shuanglei <shuanglei@hotmail.com>

   Modifications made by Matt Weir <weir@cs.fsu.edu>
*/

#ifndef _HASHALGORITHM_H
#define _HASHALGORITHM_H

#include <string>
using namespace std;

void HashLM(unsigned char* pPlain, int nPlainLen, unsigned char* pHash, string input_salt, int input_saltlen);
void HashNTLM(unsigned char* pPlain, int nPlainLen, unsigned char* pHash, string input_salt, int input_saltlen);
void HashMD2(unsigned char* pPlain, int nPlainLen, unsigned char* pHash, string input_salt, int input_saltlen);
void HashMD4(unsigned char* pPlain, int nPlainLen, unsigned char* pHash, string input_salt, int input_saltlen);
void HashMD5(unsigned char* pPlain, int nPlainLen, unsigned char* pHash, string input_salt, int input_saltlen);
void HashDoubleMD5(unsigned char* pPlain, int nPlainLen, unsigned char* pHash, string input_salt, int input_saltlen);
void HashSHA1(unsigned char* pPlain, int nPlainLen, unsigned char* pHash, string input_salt, int input_saltlen);
void HashRIPEMD160(unsigned char* pPlain, int nPlainLen, unsigned char* pHash, string input_salt, int input_saltlen);
void HashMSCACHE(unsigned char *pPlain, int nPlainLen, unsigned char* pHash, string input_salt, int input_saltlen);
//****************************************************************************
// MySQL Password Hashing
//****************************************************************************
void HashMySQL323(unsigned char* pPlain, int nPlainLen, unsigned char* pHash, string input_salt, int input_saltlen);
void HashMySQLSHA1(unsigned char* pPlain, int nPlainLen, unsigned char* pHash, string input_salt, int input_saltlen);

//****************************************************************************
// Cisco PIX Password Hashing
//****************************************************************************
void HashPIX(unsigned char* pPlain, int nPlainLen, unsigned char* pHash, string input_salt, int input_saltlen);

//****************************************************************************
// (HALF) LM CHALL hashing
void HashLMCHALL(unsigned char* pPlain, int nPlainLen, unsigned char* pHash, string input_salt, int input_saltlen);
void HashHALFLMCHALL(unsigned char* pPlain, int nPlainLen, unsigned char* pHash, string input_salt, int input_saltlen);

// From mao
void HashNTLMCHALL(unsigned char* pPlain, int nPlainLen, unsigned char* pHash, string input_salt, int input_saltlen);
void HashORACLE(unsigned char* pPlain, int nPlainLen, unsigned char* pHash, string input_salt, int saltlen);

#ifndef _WIN32
char *strupr(char *s1);
#endif
#endif
