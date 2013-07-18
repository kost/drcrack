/*
   RainbowCrack - a general propose implementation of Philippe Oechslin's faster time-memory trade-off technique.

   Copyright (C) Zhu Shuanglei <shuanglei@hotmail.com>

   Modifications made by Matt Weir <weir@cs.fsu.edu>
*/

#ifdef _WIN32
	#pragma warning(disable : 4786)
#endif

#include "HashRoutine.h"
#include "HashAlgorithm.h"

//////////////////////////////////////////////////////////////////////

CHashRoutine::CHashRoutine()
{
	// Notice: MIN_HASH_LEN <= nHashLen <= MAX_HASH_LEN


	AddHashRoutine("lm",   HashLM,   8);
	AddHashRoutine("ntlm", HashNTLM, 16);
#ifdef HAVE_MD2
	AddHashRoutine("md2",  HashMD2,  16);
#endif
	AddHashRoutine("md4",  HashMD4,  16);
	AddHashRoutine("md5",  HashMD5,  16);
	AddHashRoutine("doublemd5",  HashDoubleMD5,  16);
	AddHashRoutine("sha1", HashSHA1, 20);
	AddHashRoutine("ripemd160", HashRIPEMD160, 20);
	AddHashRoutine("mysql323", HashMySQL323, 8);
	AddHashRoutine("mysqlsha1", HashMySQLSHA1, 20);
	AddHashRoutine("ciscopix", HashPIX, 16);
	AddHashRoutine("mscache", HashMSCACHE, 16);
	AddHashRoutine("halflmchall", HashHALFLMCHALL, 8);

	// Added from mao
	AddHashRoutine("lmchall", HashLMCHALL, 24);
	AddHashRoutine("ntlmchall", HashNTLMCHALL, 24);
	AddHashRoutine("oracle", HashORACLE, 8);

}

CHashRoutine::~CHashRoutine()
{
}

void CHashRoutine::AddHashRoutine(string sHashRoutineName, HASHROUTINE pHashRoutine, int nHashLen)
{
	vHashRoutineName.push_back(sHashRoutineName);
	vHashRoutine.push_back(pHashRoutine);
	vHashLen.push_back(nHashLen);
}

string CHashRoutine::GetAllHashRoutineName()
{
	string sRet;
	int i;
	for (i = 0; i < vHashRoutineName.size(); i++)
		sRet += vHashRoutineName[i] + " ";

	return sRet;
}

void CHashRoutine::GetHashRoutine(string sHashRoutineName, HASHROUTINE& pHashRoutine, int& nHashLen)
{
	int i;
	for (i = 0; i < vHashRoutineName.size(); i++)
	{
		if (sHashRoutineName == vHashRoutineName[i])
		{
			pHashRoutine = vHashRoutine[i];
			nHashLen = vHashLen[i];
			return;
		}
	}

	pHashRoutine = NULL;
	nHashLen = 0;
}
