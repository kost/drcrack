#include <stdio.h>
#include <string>
#include <map>
#ifdef _WIN32
#include <conio.h>
#endif
#include "openssl/md4.h"
#include "time.h"
#include "signal.h"
#include "Public.h"
using namespace std;

class LM2NTLMcorrector
{
public:
	LM2NTLMcorrector();

private:
	map<unsigned char, map<int, unsigned char> > m_mapChar;
	uint64 progressCurrentCombination;
	uint64 totalCurrentCombination;
	uint64 counterOverall;
	unsigned char NTLMHash[16];
	clock_t startClock;
	int countCombinations;
	int countTotalCombinations;
	int counter;
	clock_t previousClock;
	unsigned char currentCharmap[16][128];
	bool aborting;
	string sBinary;

private:
	bool checkNTLMPassword(unsigned char* pLMPassword, int nLMPasswordLen, string& sNTLMPassword);
	bool startCorrecting(string sLMPassword, unsigned char* pNTLMHash, string& sNTLMPassword, unsigned char* pLMPassword);
	void printString(unsigned char* muteThis, int length);
	void setupCombinationAtPositions(int length, unsigned char* pMuteMe, unsigned char* pTempMute, int* jAtPos, bool* fullAtPos, int* sizeAtPos);
	bool checkPermutations(int length, unsigned char* pMuteMe, unsigned char* pTempMute, int* jAtPos, int* sizeAtPos, unsigned char* pLMPassword, string& sNTLMPassword);

	int calculateTotalCombinations(int length, int setSize);
	int factorial (int num);

	bool parseHexPassword(string hexPassword, string& sPlain);
	bool NormalizeHexString(string& sHash);
	void ParseHash(string sHash, unsigned char* pHash, int& nHashLen);
	string ByteToStr(const unsigned char* pData, int nLen);
	void addToMapW(unsigned char key, unsigned char value1, unsigned char value2);
	void fillMapW();
	void checkAbort();
	void writeEndStats();
public:
	bool LMPasswordCorrectUnicode(string sPlain, unsigned char* NTLMHash, string& sNTLMPassword);
	string getBinary();
};

