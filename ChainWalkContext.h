/*
   RainbowCrack - a general propose implementation of Philippe Oechslin's faster time-memory trade-off technique.

   Copyright (C) Zhu Shuanglei <shuanglei@hotmail.com>

   Modifications made by Matt Weir <weir@cs.fsu.edu>
*/

#ifndef _CHAINWALKCONTEXT_H
#define _CHAINWALKCONTEXT_H

#include "HashRoutine.h"
#include "Public.h"


//////////////////////////////////////////////////////////////////////////////
//used to specify what's being replaced
//Choose strings instead of chars for multichar replacements such as f->ph
typedef struct replaceStruct {
  string fromReplace[MAXREPLACESTEPS];   //replace x with y, this is x
  string toReplace[MAXREPLACESTEPS];     //replace x with y, this is y
  int minSize;                           //the minimum size of the words to use. Note, threw this in here even though it isn't a replace rule because it also narrows down the                                         //input dictionary to a smaller set. aka only apply this rule to words at least of lenght 6.
  int numReplace;                        //the number of replacements in this rule
  uint64 numWords;                       //the number of words in the input dicitonary this applies to
  string *dic[MAXDICWORDS];              //probably can make this a hell of a lot smaller. Leaving it this way now for worst case.
  replaceStruct *next;
}replaceType;

///////////////////////////////////////////////////////////////////////////////////////////////
//This structure holds one mangling rule
//Note, multiple mangling rules can be combined per JtR main rule
//Aka the first structure could hold, (lowercase all letters)
//The second structure, (pointed to by next), could hold (Add two numbers at the end)
//The third structure could hold (Add one number at the begining)
//The "next" value of the third structure would be NULL to signal the end
//So that rule would create the guess "1password11"
typedef struct ruleStruct {
  char desc[100];                //A description to show the user
  int addType;                   //Used when the user wants to choose the default list 0=none, 1=lowercase,2=uppercase,3=number,4=special
  bool addBefore;	         //add a value before the word
  bool addAfter;                 //add a value after the word
  bool upperFirst;               //uppercase the first letter
  bool upperLast;                //uppercase the last letter
  bool upperAll;                 //uppercase all the letters
  bool lowerAll;                 //lowercase all the letters
  bool repeat;                   //repeat the password, aka passworD12passworD12
  bool addAnotherWord;           //add another word from the dictionary
  bool doNothing;                //No-op
  bool replaceChar;              //replace a character, aka a->@, note, not really used anymore due to the new replacement sheme, can probably delete
  char toReplace;                //character to replace, aka 'a' , note, not really used anymore due to the new replacement scheme, can probably delete
  char replaceWith;              //character to replace it with, aka '@', not really used anymore, you get the idea
  replaceType *replaceRule;               //Points to the replacement rule dicitonary and size, this is used
  uint64 size;                      //the number of all possible passwords at this stage of the mangling rule, starts with the largest value in the leftmost rule
  ruleStruct *next;              //Points to the next rule to apply
}ruleType;


//////////////////////////////////////////////////////////////////////
//Used to store values for a thread safe version of this program
typedef struct threadStruct {
  uint64 t_nIndex;
  int t_nPlainLen;
  unsigned char t_Plain[MAX_PLAIN_LEN+1];
  unsigned char t_Hash[MAX_HASH_LEN+1]; 
}threadType;


class CChainWalkContext 
{
public:
	CChainWalkContext();
	virtual ~CChainWalkContext();

private:
	static string m_sHashRoutineName;
	static HASHROUTINE m_pHashRoutine;							// Configuration
	static int m_nHashLen;										// Configuration

	static unsigned char m_PlainCharset[256];					// Configuration
	static int m_nPlainCharsetLen;								// Configuration
	static int m_nPlainLenMin;									// Configuration
	static int m_nPlainLenMax;									// Configuration
	static string m_sPlainCharsetName;
	static string m_sPlainCharsetContent;
	static uint64 m_nPlainSpaceUpToX[MAX_PLAIN_LEN + 1];		// Performance consideration
	static uint64 m_nPlainSpaceTotal;							// Performance consideration

	static int m_nRainbowTableIndex;							// Configuration
	static uint64 m_nReduceOffset;								// Performance consideration

	// Context
	uint64 m_nIndex;
	unsigned char m_Plain[MAX_PLAIN_LEN];
	int m_nPlainLen;
	unsigned char m_Hash[MAX_HASH_LEN];

        //--added----------------------//
        static bool m_isDictionary;     //Used to specify if it uses the traditional rainbowtable generation, or the new dictionary based generation
	static string m_sDicName;                //the filename of dictionary file
	static string m_sRuleName;               //the filename of the rule file
	static uint64 m_nDicSize;                //the number of words in the input dictionary
	static string m_dicWords[MAXDICWORDS];   //the actual words from the input dictionary
	static int m_nRuleSize;                  //the number of rules in the current Rainbow Table
        static ruleType m_rules[MAXRULES];       //the actual rules to use
        static replaceType *m_replaceRules;       //the replacement rules
        static uint64 m_start[MAXRULES];         //the starting index value for the rule
        static uint64 m_end[MAXRULES];           //the ending index value for the rule
        static char m_special[50];               //the list of special characters, (used for insertion)
        static char m_upper[50];                 //the list of uppercase characters, (used for insertion)
        static char m_lower[50];                 //the list of lowercase characters, (used for insertion)
        static char m_number[50];                //the list of numbers, (used for insertion)
        static int m_specialSize;                //the number of special characters
        static int m_upperSize;                  //the number of upper charaters
        static int m_lowerSize;                  //the number of lower characters
        static int m_numberSize;                 //the number of numbers
	static bool m_newTableType;     //when processing new tables, tells it if it needs to recompute the target hash chains
        static float m_version;                  //used to tell what version the tables are, used for backwards compatability
        static string m_salt;                    //the salt value
	static int m_saltLen;			 //the length of the salt
private:
	static bool LoadCharset(string sName);
        static int initRuleType(ruleType *tempRule);
        static bool initReplaceType(replaceType *tempReplace);
        static int upperCase(char *input);
        static int lowerCase(char *input);
	static int doReplaceChar(string *input, string toReplace, string replaceWith);
public:
	static bool SetHashRoutine(string sHashRoutineName);							// Configuration
	static bool SetPlainCharset(string sCharsetName, int nPlainLenMin, int nPlainLenMax);			// Configuration
	static bool SetRainbowTableIndex(int nRainbowTableIndex);						// Configuration
	static bool SetupWithPathName(string sPathName, int& nRainbowChainLen, int& nRainbowChainCount);	// Wrapper
        static bool SetupWithConfigFile(string& sPathName, int& nRainbowChainLen, int& nRainbowChainCount);
	static string GetHashRoutineName();
	static int GetHashLen();
	static string GetPlainCharsetName();
	static string GetPlainCharsetContent();
	static int GetPlainLenMin();
	static int GetPlainLenMax();
	static uint64 GetPlainSpaceTotal();
	static int GetRainbowTableIndex();
	static void Dump();
	static bool SetDictionary(string sDicName);
	static bool SetManglingRules(string sRuleName);
	static bool SetRuleSize();
	void GenerateRandomIndex();
	void SetIndex(uint64 nIndex);
	void SetHash(unsigned char* pHash);		// The length should be m_nHashLen
        static void SetSalt(string sSalt);
	void IndexToPlain();
	void PlainToHash();
	void HashToIndex(int nPos);

   //--Thread safe versions of functions--------//
        void t_IndexToPlain(threadType *passData);
        void t_PlainToHash(threadType *passData);
        void t_HashToIndex(int nPos, threadType *passData);
        void t_GenerateRandomIndex(threadType *passData);        

	uint64 GetIndex();
	string GetPlain();
	string GetBinary();
	string GetPlainBinary();
	string GetHash();
	bool CheckHash(unsigned char* pHash);	// The length should be m_nHashLen
	static bool NeedToRebuild();  //states if the target hashes need their chains rebuild for a new table
};

#endif
