/*
   RainbowCrack - a general propose implementation of Philippe Oechslin's faster time-memory trade-off technique.

   Copyright (C) Zhu Shuanglei <shuanglei@hotmail.com>

   Modifications made by Matt Weir <weir@cs.fsu.edu>
*/

#ifndef _HASHROUTINE_H
#define _HASHROUTINE_H

#include <string>
#include <vector>

using namespace std;

typedef void (*HASHROUTINE)(unsigned char* pPlain, int nPlainLen, unsigned char* pHash, string input_Salt, int salt_Length);


class CHashRoutine  
{
public:
	CHashRoutine();
	virtual ~CHashRoutine();

private:
	vector<string>		vHashRoutineName;
	vector<HASHROUTINE>	vHashRoutine;
	vector<int>			vHashLen;
	void AddHashRoutine(string sHashRoutineName, HASHROUTINE pHashRoutine, int nHashLen);

public:
	string GetAllHashRoutineName();
	void GetHashRoutine(string sHashRoutineName, HASHROUTINE& pHashRoutine, int& nHashLen);
};

#endif
