/*
   RainbowCrack - a general propose implementation of Philippe Oechslin's faster time-memory trade-off technique.

   Copyright (C) Zhu Shuanglei <shuanglei@hotmail.com>

   Modifications made by Matt Weir <weir@cs.fsu.edu>
*/

#ifndef _PUBLIC_H
#define _PUBLIC_H

#include <stdio.h>

#include <string>
#include <vector>
#include <list>
#include <cstring>
#include <stdlib.h>
#include <sys/types.h>
using namespace std;

#ifdef _WIN32
	#define uint64 unsigned __int64
#else
	#define uint64 u_int64_t
#endif

struct RainbowChain
{
	uint64 nIndexS;
	uint64 nIndexE;
};

#define MAX_PLAIN_LEN 256
#define MIN_HASH_LEN  8
#define MAX_HASH_LEN  256
#define MAXDICWORDS 900000   //the maximum input dicitonary size
#define MAXRULES 100         //the maximum number of rules
#define MAXREPLACE 100       //the maximum number of rules that can have replacement options
#define MAXREPLACESTEPS 10   //the maximum number of replacements per rule
#define MAXTHREADS 10        //the maximum number of threads supported

unsigned int GetFileLen(FILE* file);
string TrimString(string s);
bool ReadLinesFromFile(string sPathName, vector<string>& vLine);
bool SeperateString(string s, string sSeperator, vector<string>& vPart);
string uint64tostr(uint64 n);
string uint64tohexstr(uint64 n);
string HexToStr(const unsigned char* pData, int nLen);
unsigned int GetAvailPhysMemorySize();
void ParseHash(string sHash, unsigned char* pHash, int& nHashLen);

void Logo();

#endif
