/*
   RainbowCrack - a general propose implementation of Philippe Oechslin's faster time-memory trade-off technique.

   Copyright (C) Zhu Shuanglei <shuanglei@hotmail.com>

   Modifications made by Matt Weir <weir@cs.fsu.edu>
*/

#ifdef _WIN32
	#pragma warning(disable : 4786)
#endif

#include "ChainWalkContext.h"

#include <ctype.h>
#include <openssl/rand.h>
#include <fstream>
#ifdef _WIN32
	#pragma comment(lib, "libeay32.lib")
#endif

//////////////////////////////////////////////////////////////////////

string CChainWalkContext::m_sHashRoutineName;
HASHROUTINE CChainWalkContext::m_pHashRoutine;
int CChainWalkContext::m_nHashLen;

unsigned char CChainWalkContext::m_PlainCharset[256];
int CChainWalkContext::m_nPlainCharsetLen;
int CChainWalkContext::m_nPlainLenMin;
int CChainWalkContext::m_nPlainLenMax;
string CChainWalkContext::m_sPlainCharsetName;
string CChainWalkContext::m_sPlainCharsetContent;
uint64 CChainWalkContext::m_nPlainSpaceUpToX[MAX_PLAIN_LEN + 1];
uint64 CChainWalkContext::m_nPlainSpaceTotal;


int CChainWalkContext::m_nRainbowTableIndex;
uint64 CChainWalkContext::m_nReduceOffset;

//---Added---//
bool CChainWalkContext::m_isDictionary;
string CChainWalkContext::m_sDicName;
string CChainWalkContext::m_sRuleName;
string CChainWalkContext::m_dicWords[MAXDICWORDS];
uint64 CChainWalkContext::m_nDicSize;
uint64 CChainWalkContext::m_start[MAXRULES];
uint64 CChainWalkContext::m_end[MAXRULES];
int    CChainWalkContext::m_nRuleSize;
int    CChainWalkContext::m_specialSize;
int    CChainWalkContext::m_lowerSize;
int    CChainWalkContext::m_upperSize;
int    CChainWalkContext::m_numberSize;
char   CChainWalkContext::m_special[50];
char   CChainWalkContext::m_lower[50];
char   CChainWalkContext::m_upper[50];
char   CChainWalkContext::m_number[50];
ruleType CChainWalkContext::m_rules[MAXRULES];
bool   CChainWalkContext::m_newTableType;
replaceType *CChainWalkContext::m_replaceRules;
float  CChainWalkContext::m_version;
string CChainWalkContext::m_salt;
int    CChainWalkContext::m_saltLen;
//////////////////////////////////////////////////////////////////////

CChainWalkContext::CChainWalkContext()
{
}

CChainWalkContext::~CChainWalkContext()
{
}

bool CChainWalkContext::LoadCharset(string sName)
{
	if (sName == "byte")
	{
		int i;
		for (i = 0x00; i <= 0xff; i++)
			m_PlainCharset[i] = i;
		m_nPlainCharsetLen = 256;
		m_sPlainCharsetName = sName;
		m_sPlainCharsetContent = "0x00, 0x01, ... 0xff";
		return true;
	}
        printf("Running LoadCharset\n");
	vector<string> vLine;
	if (ReadLinesFromFile("charset.txt", vLine))
	{
		int i;
		for (i = 0; i < vLine.size(); i++)
		{
			// Filter comment
			if (vLine[i][0] == '#')
				continue;

			vector<string> vPart;
			if (SeperateString(vLine[i], "=", vPart))
			{
				// sCharsetName
				string sCharsetName = TrimString(vPart[0]);
				if (sCharsetName == "")
					continue;

				// sCharsetName charset check
				bool fCharsetNameCheckPass = true;
				int j;
				for (j = 0; j < sCharsetName.size(); j++)
				{
					if (   !isalpha(sCharsetName[j])
						&& !isdigit(sCharsetName[j])
						&& (sCharsetName[j] != '-'))
					{
						fCharsetNameCheckPass = false;
						break;
					}
				}
				if (!fCharsetNameCheckPass)
				{
					printf("invalid charset name %s in charset configuration file\n", sCharsetName.c_str());
					continue;
				}

				// sCharsetContent
				string sCharsetContent = TrimString(vPart[1]);
				if (sCharsetContent == "" || sCharsetContent == "[]")
					continue;
				if (sCharsetContent[0] != '[' || sCharsetContent[sCharsetContent.size() - 1] != ']')
				{
					printf("invalid charset content %s in charset configuration file\n", sCharsetContent.c_str());
					continue;
				}
				sCharsetContent = sCharsetContent.substr(1, sCharsetContent.size() - 2);
				if (sCharsetContent.size() > 256)
				{
					printf("charset content %s too long\n", sCharsetContent.c_str());
					continue;
				}

				printf("%s = [%s]\n", sCharsetName.c_str(), sCharsetContent.c_str());

				// Is it the wanted charset?
				if (sCharsetName == sName)
				{
					m_nPlainCharsetLen = sCharsetContent.size();
					memcpy(m_PlainCharset, sCharsetContent.c_str(), m_nPlainCharsetLen);
					m_sPlainCharsetName = sCharsetName;
					m_sPlainCharsetContent = sCharsetContent;
					return true;
				}
			}
		}
		printf("charset %s not found in charset.txt\n", sName.c_str());
	}
	else
		printf("can't open charset configuration file\n");

	return false;
}

//////////////////////////////////////////////////////////////////////

bool CChainWalkContext::SetHashRoutine(string sHashRoutineName)
{
	CHashRoutine hr;
	hr.GetHashRoutine(sHashRoutineName, m_pHashRoutine, m_nHashLen);
	if (m_pHashRoutine != NULL)
	{
		m_sHashRoutineName = sHashRoutineName;
		if ((sHashRoutineName.compare("mscache")!=0)&&(sHashRoutineName.compare("oracle")!=0)) { //sanity check
                  m_salt="-1";
		}
		return true;
	}
	else
		return false;
}

bool CChainWalkContext::SetPlainCharset(string sCharsetName, int nPlainLenMin, int nPlainLenMax)
{
	// m_PlainCharset, m_nPlainCharsetLen, m_sPlainCharsetName, m_sPlainCharsetContent
	if (!LoadCharset(sCharsetName))
		return false;

	// m_nPlainLenMin, m_nPlainLenMax
	if (nPlainLenMin < 1 || nPlainLenMax > MAX_PLAIN_LEN || nPlainLenMin > nPlainLenMax)
	{
		printf("invalid plaintext length range: %d - %d\n", nPlainLenMin, nPlainLenMax);
		return false;
	}
	m_nPlainLenMin = nPlainLenMin;
	m_nPlainLenMax = nPlainLenMax;

	// m_nPlainSpaceUpToX
	m_nPlainSpaceUpToX[0] = 0;
	uint64 nTemp = 1;
	int i;
	for (i = 1; i <= m_nPlainLenMax; i++)
	{
		nTemp *= m_nPlainCharsetLen;
		if (i < m_nPlainLenMin)
			m_nPlainSpaceUpToX[i] = 0;
		else
			m_nPlainSpaceUpToX[i] = m_nPlainSpaceUpToX[i - 1] + nTemp;
	}

	m_nPlainSpaceTotal = m_nPlainSpaceUpToX[m_nPlainLenMax];

	return true;
}

bool CChainWalkContext::SetDictionary(string sDicName) {
  int count;
  char fileName[256];
  snprintf(fileName,255,sDicName.c_str());
  ifstream inputFile(fileName);
  string nextWord;
  replaceType *curReplace;
  int i;
  bool match;
  
  printf("Reading in the dictionary\n");
  m_isDictionary=true;
  m_sDicName = sDicName;
  if (!inputFile.is_open()) {
    return false;
  }
  count=0;
  getline(inputFile,nextWord);
  while ((!inputFile.eof())&&(count<MAXDICWORDS)) {
    if (nextWord.size()>0) {
      if ((nextWord[nextWord.size()-1]=='\r')||(nextWord[nextWord.size()-1]=='\n')) { //remove carriage return or newline if it exists
        nextWord.resize(nextWord.size()-1);  
      }
      if (nextWord.size()>0) {
        m_dicWords[count]=nextWord;
        //----Get the info for character replacement---//
        curReplace=m_replaceRules;
        while (curReplace!=NULL) {
          match=true;
          for (i=0;i<curReplace->numReplace;i++) {
            if (((curReplace->fromReplace[i]!=">")&&(nextWord.find(curReplace->fromReplace[i])==string::npos))||(nextWord.size()<curReplace->minSize)) {
              match=false;
              break;
            }
          }
          if (match) { //the word can work for that mangling rule
            curReplace->dic[curReplace->numWords]=&m_dicWords[count];
            curReplace->numWords++;
          }
          curReplace=curReplace->next;
        } 
        count++;   
      }
    }
    getline(inputFile,nextWord);
  }
  inputFile.close();
  if (count==0) {
    return false;
  }
  printf("Dictionary Size = %i\n",count); 
  m_nDicSize=count;
//  m_nPlainSpaceTotal=count;
  return true;
}

bool CChainWalkContext::SetManglingRules(string sRuleName) {
  int count;
  int i;
  FILE *loadFile;
  char fileName[256];
  char *tempChar;
  char tempString[256];
  ruleType *tempRule;
  ruleType *tempRule2;
  bool isNewPart;  //used so I know when to add a new ruleType, if false add new ruletype
  replaceType *curReplaceRule;
  replaceType *tempReplaceRule;
  int curReplaceStep;
  
  printf("Processing mangling rules\n");
  curReplaceRule=NULL;
  m_replaceRules=curReplaceRule;
  m_nRuleSize=0;
  snprintf(fileName,255,sRuleName.c_str());
  loadFile=fopen(fileName,"r");
  if (loadFile==NULL) {
    printf("ERROR: Could not open %s\n",fileName);
    return false; 
  }
  //------------First get the character set info----------------------//
  fgets(tempString,199,loadFile);
  tempChar=strstr(tempString,"<special>");
  while ((tempChar==NULL)&&(!feof(loadFile))) {
    fgets(tempString,199,loadFile);
    tempChar=strstr(tempString,"<special>");
  }
  if (tempChar==NULL) {
    printf("Error with the rule file:1\n");
    return false;
  }
  strncpy(m_special,tempString+8,49);
  m_specialSize=strlen(m_special)-1;
  m_special[m_specialSize]='\0';

  fgets(tempString,199,loadFile);
  tempChar=strstr(tempString,"<lower>");
  while ((tempChar==NULL)&&(!feof(loadFile))) {
    fgets(tempString,199,loadFile);
    tempChar=strstr(tempString,"<lower>");
  }
  if (tempChar==NULL) {
    printf("Error with the rule file:2\n");
    return false;
  }

  strncpy(m_lower,tempString+7,49);
  m_lowerSize=strlen(m_lower)-1;
  m_lower[m_lowerSize]='\0';

  fgets(tempString,199,loadFile);
  tempChar=strstr(tempString,"<upper>");
  while ((tempChar==NULL)&&(!feof(loadFile))) {
    fgets(tempString,199,loadFile);
    tempChar=strstr(tempString,"<upper>");
  }
  if (tempChar==NULL) {
    printf("Error with the rule file:3\n");
    return false;
  }

  strncpy(m_upper,tempString+7,49);
  m_upperSize=strlen(m_upper)-1;
  m_upper[m_upperSize]='\0';

  fgets(tempString,199,loadFile);
  tempChar=strstr(tempString,"<number>");
  while ((tempChar==NULL)&&(!feof(loadFile))) {
    fgets(tempString,199,loadFile);
    tempChar=strstr(tempString,"<number>");
  }
  if (tempChar==NULL) {
    printf("Error with the rule file:4\n");
    return false;
  }

  strncpy(m_number,tempString+8,49);
  m_numberSize=strlen(m_number)-1;
  m_number[m_numberSize]='\0';

  printf("special=[%s] size=%d\n",m_special,m_specialSize);
  printf("lower=[%s] size=%d\n",m_lower,m_lowerSize);
  printf("upper=[%s] size=%d\n",m_upper,m_upperSize);
  printf("number=[%s] size=%d\n",m_number,m_numberSize);

  //----------------------Now get the mangling rules-----------------------------//
  tempRule=&m_rules[0];
  initRuleType(tempRule);
  isNewPart=true; 
  curReplaceStep=0; 


  fgets(tempString,199,loadFile); 
  while (!feof(loadFile)) { 
    tempChar=strstr(tempString,"</newRule>");  //check to see if the current rule has been fully parsed
    if (tempChar!=NULL) {
      m_nRuleSize++;
      tempRule=&m_rules[m_nRuleSize];
      initRuleType(tempRule);
      isNewPart=true;
      curReplaceStep=0;
    }
    else {
      tempChar=strstr(tempString,"<addType>"); //find the addType for the current rule
      if (tempChar!=NULL) {
        tempRule->addType=atoi(tempChar+9);
        //printf("addtype=%d\n",tempRule->addType);
      }
      else {
        tempChar=strstr(tempString,"<rulePart>");
        if (tempChar!=NULL) {
          if (isNewPart) {  //It's still on the first rulepart
            isNewPart=false;
          }
          else {
            tempRule2 = new ruleType;
            initRuleType(tempRule2);
            tempRule->next=tempRule2;
            tempRule=tempRule->next;
          }
        }
        else {
          tempChar=strstr(tempString,"<jtrRule>");  //check to get the actual rule
          if (tempChar!=NULL) {
            tempChar=tempChar+9;
            tempChar[strlen(tempChar)-1]='\0'; //get rid of the newline;
            if (strncmp(tempChar,":",10)==0) {
              tempRule->doNothing=true;
            }
            else if (tempChar[0]=='l') { //lowercase all letters
              tempRule->lowerAll=true;
            }
            else if (tempChar[0]=='c') { //capitalize the first letter
              tempRule->upperFirst=true;
            }
            else if (tempChar[0]=='u') {  //uppercase all letters
              tempRule->upperAll=true;
            }
            else if (tempChar[0]=='$') {  //append letters to the end
              tempRule->addAfter=true;
            }
            else if (tempChar[0]=='^') {  //prefix letters to the start
              tempRule->addBefore=true;
            }
            else if (tempChar[0]=='e') {  //capitalize the last letter
              tempRule->upperLast=true;
            }
            else if (tempChar[0]=='d') {  //duplicate the word
              tempRule->repeat=true;
            }
            else if (tempChar[0]=='+') {  //append another dictionary word
              tempRule->addAnotherWord=true;
            }
            else if ((tempChar[0]=='s')||(tempChar[0]=='S')||(tempChar[0]=='>')) {  //substitute one letter or string for another or min length requirement
              tempRule->replaceChar=true;
              if (curReplaceRule==NULL) {         //this is the first replace rule
                curReplaceRule=new replaceType;
                initReplaceType(curReplaceRule);
                m_replaceRules=curReplaceRule;
                m_rules[m_nRuleSize].replaceRule=curReplaceRule;
              }
              else if (curReplaceStep==0) {  //this is a new replacement rule
                curReplaceRule->next = new replaceType;
                initReplaceType(curReplaceRule->next);
                curReplaceRule=curReplaceRule->next;
                m_rules[m_nRuleSize].replaceRule=curReplaceRule;
              }
              if (curReplaceRule->numReplace>=MAXREPLACESTEPS) {  //check to make sure there are not too many replacements for the current rule
                printf("I'm sorry but you are trying to have too many replacement steps in one rule\n");
                return false;
              }
              curReplaceRule->numReplace++; //increment the number of replacement rules
              if (tempChar[0]=='s') { //doing a standard character for character substitution
                if (tempChar[1]!='\0') {
                  tempRule->toReplace=tempChar[1];
                  curReplaceRule->fromReplace[curReplaceStep]=tempChar[1];
                }
                else {
                  printf("I'm sorry, there is an error with the rule\n");
                  return false;
                }
                if (tempChar[2]!='\0') {
                  tempRule->replaceWith=tempChar[2];
                  curReplaceRule->toReplace[curReplaceStep]=tempChar[2];
                }
                else {
                  printf("I'm sorry, there is an error with the rule\n");
                  return false;
                }
                curReplaceStep++;
              }
              else if (tempChar[0]=='>') { //adding a length requirement
                curReplaceRule->fromReplace[curReplaceStep]='>';
                tempRule->toReplace='>';
                if ((tempChar[1]!='\0')&&(isdigit(tempChar[1]))) {
                  tempRule->replaceWith=tempChar[1];
                  curReplaceRule->toReplace[curReplaceStep]=tempChar[1];
                }
                else {
                  printf("I'm sorry, there is an error with the rule\n");
                  return false;
                }
                if ((tempChar[2]!='\0')&&(isdigit(tempChar[1]))) {
                  curReplaceRule->toReplace[curReplaceStep].append(1,tempChar[2]);
                }
                curReplaceRule->minSize=atoi(curReplaceRule->toReplace[curReplaceStep].c_str());
                printf("size of min is %d\n",curReplaceRule->minSize);
                curReplaceStep++;
              }
            }
            else {   //if the rule is not recognized
              printf("I'm sorry but this rainbow table generator does not recognize that jtr rule\n");
              printf("the rule is=%s\n",tempChar);
              return false;
            }
          }
        }
      }
    }
    fgets(tempString,199,loadFile);
  }
  //---trim replace rules to remove duplicates-------------//
  curReplaceRule=m_replaceRules;
  bool duplicateReplace;
  while (curReplaceRule!=NULL) {
    tempReplaceRule=curReplaceRule;
    while (tempReplaceRule->next!=NULL) {
      duplicateReplace=true;
      for (i=0;i<curReplaceRule->numReplace; i++) {
        if ((curReplaceRule->fromReplace[i].compare(tempReplaceRule->next->fromReplace[i])!=0)||(curReplaceRule->toReplace[i].compare(tempReplaceRule->next->toReplace[i])!=0)) {
          duplicateReplace=false;
          break;
        }
      }
      if (duplicateReplace) { //it is a duplicate
        for (i=0;i<m_nRuleSize; i++) {
          if (m_rules[i].replaceRule==tempReplaceRule->next) {
            m_rules[i].replaceRule=curReplaceRule;
          }
        }
        tempReplaceRule->next=tempReplaceRule->next->next;
      }
      else {
        tempReplaceRule=tempReplaceRule->next;
      }
    }
    curReplaceRule=curReplaceRule->next;
  }       
  return true;
}


///////////////////////////////////////////////////////////////////////////
//This function determines how many items each rule will create and the total index size
bool CChainWalkContext::SetRuleSize(){
  int i;
  int j;
  uint64 prevSize;  //tempValue to calculate how many possible values there are
  ruleType *tempRule;
  uint64 baseSize;

  printf("Figuring out Rule Size\n");
  //---------------Now figure out size information-----------------------------------//
  for (i=0;i<m_nRuleSize;i++) {
    tempRule=&m_rules[i];
    //first find out if there is a replacement rule
    if (tempRule->replaceRule==NULL) { //no replacment rules
      baseSize=m_nDicSize;
    }    
    else {
      baseSize=tempRule->replaceRule->numWords;
      if (baseSize==0) {
        printf("Error, you have a rule where no words match it from your input dictionary\n");
        return false;
      } 
    }
    while (tempRule->size==0) {
      while ((tempRule->next!=NULL)&&(tempRule->next->size==0)) { //go to the last unfinished part of the rule
        tempRule=tempRule->next;
      }
      if (tempRule->next==NULL) {
        prevSize=baseSize;
      }
      else {
        prevSize= tempRule->next->size;
      }
      if ((tempRule->addBefore)||(tempRule->addAfter)) { //if adding a category to the dictionary word
        if (tempRule->addType==1) {
          tempRule->size=prevSize*m_lowerSize;
        }
        else if (tempRule->addType==2) {
          tempRule->size=prevSize*m_upperSize;
        }
        else if (tempRule->addType==3) {
          tempRule->size=prevSize*m_numberSize;
        }
        else if (tempRule->addType==4) {
          tempRule->size=prevSize*m_specialSize;
        }
        else {
          printf("I'm sorry, but we currently don't support this type of rule\n");
          return false;
        }
      }
      else if (tempRule->addAnotherWord) { //append another word from the dictionary
        tempRule->size=prevSize*m_nDicSize;
      }
      else {            //if just doing a rule that doesn't generate any additional guesses
        tempRule->size=prevSize;
      }
      tempRule=&m_rules[i];
    }
    printf("Index Size for rule %d is=%s\n",i,uint64tostr(tempRule->size).c_str());
  }

  //------------Now figure out the total index size------------//
  prevSize=0;
  for (i=0;i<m_nRuleSize;i++) {
    m_start[i]=prevSize;
    prevSize=prevSize+m_rules[i].size;
    m_end[i]=prevSize-1;
//    printf("start for %d is=%d\n",i,m_start[i]);
//    printf("end for %d is=%d\n",i,m_end[i]);

  }
  m_nPlainSpaceTotal=prevSize;
  printf("the total Size=%s\n",uint64tostr(m_nPlainSpaceTotal).c_str());

  return true;
}



///////////////////////////////////////////////////////////////////////////
//This function just initilizes a new Ruletype;
int CChainWalkContext::initRuleType(ruleType *tempRule) {
  tempRule->addType=0;
  tempRule->addBefore =false;
  tempRule->addAfter=false;
  tempRule->upperFirst=false;
  tempRule->upperLast=false;
  tempRule->upperAll=false;
  tempRule->lowerAll=false;
  tempRule->doNothing=false;
  tempRule->replaceChar=false;
  tempRule->repeat=false;
  tempRule->addAnotherWord=false;
  tempRule->size=0;
  tempRule->replaceRule=NULL;
  tempRule->next=NULL;
  return 0;
}

bool CChainWalkContext::initReplaceType(replaceType *tempReplace) {
  tempReplace->numWords=0;
  tempReplace->numReplace=0;
  return true;
}

bool CChainWalkContext::SetRainbowTableIndex(int nRainbowTableIndex)
{
	if (nRainbowTableIndex < 0)
		return false;
	m_nRainbowTableIndex = nRainbowTableIndex;
	m_nReduceOffset = 65536 * nRainbowTableIndex;

	return true;
}

bool CChainWalkContext::SetupWithPathName(string sPathName, int& nRainbowChainLen, int& nRainbowChainCount)
{
	// something like lm_alpha#1-7_0_100x16_test.rt
	int nIndex;
        string sHashRoutineName;
	int nRainbowTableIndex;
	string sCharsetDefinition;
	string sCharsetName;
	int nPlainLenMin;
	int nPlainLenMax;

	if (sPathName.size() < 3)
	{
		printf("%s is not a rainbow table\n", sPathName.c_str());
		return false;
	}
        if (sPathName.substr(sPathName.size() -3) == ".rt") { 

	        #ifdef _WIN32
	        nIndex = sPathName.find_last_of('\\');
		#else
    	    	nIndex = sPathName.find_last_of('/');
		#endif


		// Parse
		vector<string> vPart;
		if (!SeperateString(sPathName, "___x_", vPart))
		{
			printf("filename %s not identified\n", sPathName.c_str());
			return false;
		}

		sHashRoutineName = vPart[0];
		nRainbowTableIndex = atoi(vPart[2].c_str());
		nRainbowChainLen = atoi(vPart[3].c_str());
		nRainbowChainCount = atoi(vPart[4].c_str());

		// Parse charset definition
		sCharsetDefinition = vPart[1];
		if (sCharsetDefinition.find('#') == -1)		// For backward compatibility, "#1-7" is implied
		{
			sCharsetName = sCharsetDefinition;
			nPlainLenMin = 1;
			nPlainLenMax = 7;
		}
		else
		{
			vector<string> vCharsetDefinitionPart;
			if (!SeperateString(sCharsetDefinition, "#-", vCharsetDefinitionPart))
			{
				printf("filename %s not identified\n", sPathName.c_str());
				return false;	
			}
			else
			{
				sCharsetName = vCharsetDefinitionPart[0];
				nPlainLenMin = atoi(vCharsetDefinitionPart[1].c_str());
				nPlainLenMax = atoi(vCharsetDefinitionPart[2].c_str());
			}
		}
        }
	else {
          	printf("%s is not a rainbow table\n", sPathName.c_str());
          	return false;
        }
        
	// Setup
	if (!SetHashRoutine(sHashRoutineName))
	{
		printf("hash routine %s not supported\n", sHashRoutineName.c_str());
		return false;
	}
        if (!m_isDictionary) {
	  if (!SetPlainCharset(sCharsetName, nPlainLenMin, nPlainLenMax))
	  	return false;
        }
	if (!SetRainbowTableIndex(nRainbowTableIndex))
	{
		printf("invalid rainbow table index %d\n", nRainbowTableIndex);
		return false;
	}

	return true;
}

bool CChainWalkContext::SetupWithConfigFile(string& sPathName, int& nRainbowChainLen, int& nRainbowChainCount)
{
  // something like lm_alpha#1-7_0_100x16_test.rt
  int nIndex;
  string sHashRoutineName;
  int nRainbowTableIndex;
  string sCharsetDefinition;
  string sCharsetName;
  int nPlainLenMin;
  int nPlainLenMax;
  FILE *configFile;         //the configuration file
  char tempString[256];     //a temporary string used to parse input
  char *tempChar;           //used to parse the input string
  string compareString;     //used to tell if the dictionary/mangling rules need to be read in
  int    compareInt;        //used to tell if the chainlen or index has changed
  bool newDic;
  bool newRules;
  string prefixInfo;        //the path prefix of the config file being opened
  size_t prefixLoc;         //used to tell where the prifix info ends and the filename begins
  if ((sPathName.size()>=4)&&(sPathName.substr(sPathName.size() -4) == ".cfg")) {
    m_newTableType=false;
    configFile=fopen(sPathName.c_str(),"r");
    if (configFile==NULL) {
      printf("The config file could not be opened\n");
      return false;
    }
    //------------Find the prefix info so additonal files will be opened from the right location-------//
    prefixLoc=sPathName.find_last_of("/");
    if (prefixLoc!=-1) { //there is a prefix
      prefixInfo=sPathName.substr(0,prefixLoc);
      prefixInfo.append("/");
    }

    //------------Parse the config file for info-------------------------------------------------------//
    if (fgets(tempString,255,configFile)!=NULL) {
      if (strstr(tempString,"<Type>dictionary")!=NULL) {
        m_isDictionary=true;
      }
      else {
        //--currently we don't have support for non-dictionary config files, remove the return false when we do--//
        m_isDictionary=false;
        return false;
      }
    }
    else {
      printf("The config file is empty\n");
      fclose(configFile);
      return false;
    }

    if (fgets(tempString,255,configFile)==NULL) {
      printf("Error parsing config file\n");
      fclose(configFile);
      return false;
    }
    tempChar=strstr(tempString,"<Version>");
    if (tempChar!=NULL) {  //if there is version info in the config file
      m_version=atof(tempChar+9);
      if (fgets(tempString,255,configFile)==NULL) { //get the next line
        printf("Error parsing config file\n");
        fclose(configFile);
        return false;
      }
    }
    else {
      m_version=1.0;
    }
    printf("Version = %2f\n",m_version);
    tempChar=strstr(tempString,"<Hash>");
    if (tempChar==NULL) {
      printf("Error parsing config file\n");
      fclose(configFile);
      return false;
    }
    sHashRoutineName=tempChar+6;
    sHashRoutineName.resize(sHashRoutineName.size()-1);
    printf("Hash=%s\n",sHashRoutineName.c_str());

    if (fgets(tempString,255,configFile)==NULL) {
      printf("Error parsing config file\n");
      fclose(configFile);
      return false;
    }

    //get the salt if it exists
    tempChar=strstr(tempString,"<Salt>");
    if (tempChar!=NULL) { //if the salt exists
      m_salt=tempChar+6;
      m_salt.resize(m_salt.size()-1);
      m_saltLen=m_salt.size();
      printf("Salt=%s\n",m_salt.c_str());
      printf("Salt Length=%d\n",m_saltLen);
      if (fgets(tempString,255,configFile)==NULL) { //get the index value
        printf("Error parsing config file\n");
        fclose(configFile);
        return false;
      }
    }      
    else if (sHashRoutineName.compare("mscache")==0) { //no salt specified
      m_salt="administrator";
      printf("Salt=%s\n",m_salt.c_str());
      m_saltLen=m_salt.size();
    }
    else if (sHashRoutineName.compare("oracle")==0) { //no salt specified
      m_salt="SYS";
      printf("Salt=%s\n",m_salt.c_str());
      m_saltLen=m_salt.size();
    }
    //Get the Index Value
    tempChar=strstr(tempString,"<Index>");
    if (tempChar==NULL) {
      printf("Error parsing config file\n");
      fclose(configFile);
      return false;
    }
    compareInt=atoi(tempChar+7);
    if (compareInt!=nRainbowTableIndex) {
      m_newTableType=true;
    }
    nRainbowTableIndex=compareInt;   
    printf("index=%i\n",nRainbowTableIndex);

    //Get the Chain Length value
    if (fgets(tempString,255,configFile)==NULL) {
      printf("Error parsing config file\n");
      fclose(configFile);
      return false;
    }
    tempChar=strstr(tempString,"<ChainLen>");
    if (tempChar==NULL) {
      printf("Error parsing config file\n");
      fclose(configFile);
      return false;
    }
    compareInt = atoi(tempChar+10);
    if (compareInt!=nRainbowChainLen) {
      m_newTableType = true;
    }
    nRainbowChainLen=compareInt;  
    printf("ChainLen=%i\n",nRainbowChainLen);

    //Get the Chain Count value
    if (fgets(tempString,255,configFile)==NULL) {
      printf("Error parsing config file\n");
      fclose(configFile);
      return false;
    }
    tempChar=strstr(tempString,"<ChainCount>");
    if (tempChar==NULL) {
      printf("Error parsing config file\n");
      fclose(configFile);
      return false;
    }
    nRainbowChainCount=atoi(tempChar+12);  
    printf("ChainCount=%i\n",nRainbowChainCount);

    if (m_isDictionary) {

      //Get the RainbowTable Name
      if (fgets(tempString,255,configFile)==NULL) {
        printf("Error parsing config file\n");
        fclose(configFile);
        return false;
      }
      tempChar=strstr(tempString,"<RainbowTable>");
      if (tempChar==NULL) {
        printf("Error parsing config file\n");
        fclose(configFile);
        return false;
      }
      sPathName=tempChar+14;  
      sPathName.resize(sPathName.size()-1);
      if (prefixLoc!=-1) {
        sPathName.insert(0,prefixInfo);
      }
      printf("RainbowTable=%s\n",sPathName.c_str());

      //Get the Dictionary File
      if (fgets(tempString,255,configFile)==NULL) {
        printf("Error parsing config file\n");
        fclose(configFile);
        return false;
      }
      tempChar=strstr(tempString,"<Dictionary>");
      if (tempChar==NULL) {
        printf("Error parsing config file\n");
        fclose(configFile);
        return false;
      }
      compareString=tempChar+12;
      compareString.resize(compareString.size()-1);
      if (prefixLoc!=-1) {
        compareString.insert(0,prefixInfo);
      }
      if (m_sDicName.compare(compareString)!=0){
        m_newTableType=true;
        newDic=true;
      }
      else {
        newDic=false;
      }
      m_sDicName=compareString;           
      printf("Dictionary=%s\n",m_sDicName.c_str());

      //Get the Word Mangling File
      if (fgets(tempString,255,configFile)==NULL) {
        printf("Error parsing config file\n");
        fclose(configFile);
        return false;
      }
      tempChar=strstr(tempString,"<ManglingRules>");
      if (tempChar==NULL) {
        printf("Error parsing config file\n");
        fclose(configFile);
        return false;
      }
      compareString=tempChar+15;
      compareString.resize(compareString.size()-1);
      if (prefixLoc!=-1) {
        compareString.insert(0,prefixInfo);
      }
      if (m_sRuleName.compare(compareString)!=0) {
        m_newTableType=true;
        newRules=true;
      }
      else {
        newRules=false;
      }
      m_sRuleName=compareString;                
      printf("ManglingRules=%s\n",m_sRuleName.c_str());

      fclose(configFile);
     
      //-------First find out the word mangling rules---------// 
      if (newRules) {
        printf("NEWRULES IS TRUE\n");
        if (!SetManglingRules(m_sRuleName)){
          printf("Could not process mangling rules\n");
          m_sDicName.clear();
          m_sRuleName.clear();
          return false;
        }
      }
      //-------Next read in the input dictionary, done second since we categorize the words at this time based on the rules--------//
      if (newDic) {
        if (!SetDictionary(m_sDicName)) {
          printf("Could not process dictionary\n");
          m_sDicName.clear();
          m_sRuleName.clear();
          return false;
        }
      }
      //------Calculate how many guesses will be created for each rule and the final index size-------------------------//
      if ((newRules)||(newDic)) {
        printf("Calculating rule and index size\n");
        if (!SetRuleSize()) {
          printf("Error calculating the final rule size\n");
          m_sDicName.clear();
          return false;
        }
      }
    }
    else {
      //In the future, add support for brute-force rainbowtables with config files here
      printf("I'm sorry, but this lazy coder hasn't added support for non-dictionary based config files\n");
      fclose(configFile);
      return false;
    }
  }
  else {
    printf("%s is not a rainbow table config file\n", sPathName.c_str());
    return false;
  }

  // Setup
  if (!SetHashRoutine(sHashRoutineName)) {
    printf("hash routine %s not supported\n", sHashRoutineName.c_str());
    return false;
  }
  if (!SetRainbowTableIndex(nRainbowTableIndex)) {
    printf("invalid rainbow table index %d\n", nRainbowTableIndex);
    return false;
  }
  return true;
}



string CChainWalkContext::GetHashRoutineName()
{
	return m_sHashRoutineName;
}

int CChainWalkContext::GetHashLen()
{
	return m_nHashLen;
}

bool CChainWalkContext::NeedToRebuild() {
  if ((m_isDictionary)&&(!m_newTableType)) {
    return false;
  }
  return true;
}

string CChainWalkContext::GetPlainCharsetName()
{
	return m_sPlainCharsetName;
}

string CChainWalkContext::GetPlainCharsetContent()
{
	return m_sPlainCharsetContent;
}

int CChainWalkContext::GetPlainLenMin()
{
	return m_nPlainLenMin;
}

int CChainWalkContext::GetPlainLenMax()
{
	return m_nPlainLenMax;
}

uint64 CChainWalkContext::GetPlainSpaceTotal()
{
	return m_nPlainSpaceTotal;
}

int CChainWalkContext::GetRainbowTableIndex()
{
	return m_nRainbowTableIndex;
}

void CChainWalkContext::Dump()
{
	printf("hash routine: %s\n", m_sHashRoutineName.c_str());
	printf("hash length: %d\n", m_nHashLen);

	printf("plain charset: ");
	int i;
	for (i = 0; i < m_nPlainCharsetLen; i++)
	{
		if (isprint(m_PlainCharset[i]))
			printf("%c", m_PlainCharset[i]);
		else
			printf("?");
	}
	printf("\n");

	printf("plain charset in hex: ");
	for (i = 0; i < m_nPlainCharsetLen; i++)
		printf("%02x ", m_PlainCharset[i]);
	printf("\n");

	printf("plain length range: %d - %d\n", m_nPlainLenMin, m_nPlainLenMax);
	printf("plain charset name: %s\n", m_sPlainCharsetName.c_str());
	//printf("plain charset content: %s\n", m_sPlainCharsetContent.c_str());
	//for (i = 0; i <= m_nPlainLenMax; i++)
	//	printf("plain space up to %d: %s\n", i, uint64tostr(m_nPlainSpaceUpToX[i]).c_str());
	printf("plain space total: %s\n", uint64tostr(m_nPlainSpaceTotal).c_str());

	printf("rainbow table index: %d\n", m_nRainbowTableIndex);
	printf("reduce offset: %s\n", uint64tostr(m_nReduceOffset).c_str());
	printf("\n");
}

void CChainWalkContext::GenerateRandomIndex()
{
	RAND_bytes((unsigned char*)&m_nIndex, 8);
	m_nIndex = m_nIndex % m_nPlainSpaceTotal;
}

void CChainWalkContext::t_GenerateRandomIndex(threadType *passData) {
        RAND_bytes((unsigned char*)&passData->t_nIndex, 8);
        passData->t_nIndex = passData->t_nIndex % m_nPlainSpaceTotal;
}

void CChainWalkContext::SetIndex(uint64 nIndex)
{
	m_nIndex = nIndex;
}

void CChainWalkContext::SetHash(unsigned char* pHash)
{
	memcpy(m_Hash, pHash, m_nHashLen);
}

void CChainWalkContext::SetSalt(string sSalt) {
	m_salt=sSalt;
	m_saltLen = sSalt.size();
}

void CChainWalkContext::IndexToPlain() {
  int i;
  int j;
  uint64 tempIndex;
  ruleType *tempRule;
  string tempWord; //used to hold the plaintext word while it is being mangled
  char tempChar;   //used to hold the character to insert
  string tempInsertBefore;  //Used to insert a value before the dictionary word, (added so the insertions go in order)
  uint64 nIndexOfX;
  bool canInsertBefore;  //if there is a value to be inserted before the word
  if (!m_isDictionary) {
    for (i = m_nPlainLenMax - 1; i >= m_nPlainLenMin - 1; i--) {
      if (m_nIndex >= m_nPlainSpaceUpToX[i]) {
        m_nPlainLen = i + 1;
	break;
      }
    }

    nIndexOfX = m_nIndex - m_nPlainSpaceUpToX[m_nPlainLen - 1];
    /*
    // Slow version
    for (i = m_nPlainLen - 1; i >= 0; i--) {
      m_Plain[i] = m_PlainCharset[nIndexOfX % m_nPlainCharsetLen];
      nIndexOfX /= m_nPlainCharsetLen; 
    }
    */

    // Fast version
    for (i = m_nPlainLen - 1; i >= 0; i--) {
#ifdef _WIN32
      if (nIndexOfX < 0x100000000I64)
        break;
#else
      if (nIndexOfX < 0x100000000llu)
	break;
#endif

      m_Plain[i] = m_PlainCharset[nIndexOfX % m_nPlainCharsetLen];
      nIndexOfX /= m_nPlainCharsetLen;
    }
    unsigned int nIndexOfX32 = (unsigned int)nIndexOfX;
    for (; i >= 0; i--) {
      //m_Plain[i] = m_PlainCharset[nIndexOfX32 % m_nPlainCharsetLen];
      //nIndexOfX32 /= m_nPlainCharsetLen;

      unsigned int nPlainCharsetLen = m_nPlainCharsetLen;
      unsigned int nTemp;
#ifdef _WIN32
      __asm {
		mov eax, nIndexOfX32
		xor edx, edx
		div nPlainCharsetLen
		mov nIndexOfX32, eax
		mov nTemp, edx
      }
#else
      __asm__ __volatile__ (	"mov %2, %%eax;"
		"xor %%edx, %%edx;"
		"divl %3;"
		"mov %%eax, %0;"
		"mov %%edx, %1;"
		: "=m"(nIndexOfX32), "=m"(nTemp)
		: "m"(nIndexOfX32), "m"(nPlainCharsetLen)
		: "%eax", "%edx"
		);
#endif
      m_Plain[i] = m_PlainCharset[nTemp];
    }
  }
  else {  //-----Doing a dictionary based attack----------------//
    i=0;
    while ((i<m_nRuleSize)&&(m_nIndex>m_end[i])) {  //first find the right rule to apply
      i++;
    }
    if (i==m_nRuleSize) {
      printf("ERROR INDEX IS OUT OF RANGE, index value=%d, maxRule=%d\n",m_nIndex,m_nRuleSize);
      i--;
    }
    tempRule =&m_rules[i];
    nIndexOfX=m_nIndex-m_start[i];
    //tempWord=m_dicWords[nIndexOfX%m_nDicSize];  //first figure out which dictionary word to use
    //------First find the dictionary word to use and do any letter replacement----------//
    if (tempRule->replaceRule==NULL) { //no replacement
      tempWord=m_dicWords[nIndexOfX%m_nDicSize];
      nIndexOfX=nIndexOfX / m_nDicSize;  //update the Index
    }
    else {   //replacement rule
      tempWord=tempRule->replaceRule->dic[nIndexOfX%tempRule->replaceRule->numWords][0];
      for (i=0;i<tempRule->replaceRule->numReplace;i++) {
        if (tempRule->replaceRule->fromReplace[i]!=">") {
          doReplaceChar(&tempWord, tempRule->replaceRule->fromReplace[i],tempRule->replaceRule->toReplace[i]);
        }
      }    
      nIndexOfX=nIndexOfX / tempRule->replaceRule->numWords;
    }


    tempInsertBefore.clear();  //initilize the insert before info
    canInsertBefore=false;

    while (tempRule!=NULL) {   //while there are still rule parts to process
      if (tempRule->upperFirst) { //uppercase the first letter
        upperCase(&tempWord[0]);
      }
      else if (tempRule->upperAll) {   //uppercase all the letters
        for (j=0;j<tempWord.size();j++) {
          upperCase(&tempWord[j]);
        }
      }
      else if (tempRule->lowerAll) {     //lowercase all the letters
        for (j=0;j<tempWord.size();j++) {
          lowerCase(&tempWord[j]);
        }
      }
      else if (tempRule->upperLast) { //uppercase the last letter
        upperCase(&tempWord[tempWord.size()-1]);
      }
      else if (tempRule->repeat) {    //repeat the word, aka passwordpassword
        string addString = tempWord;   //using this so the append operation will work correctly, aka can't append a string to itself
        tempWord.append(addString);
      }
      else if (tempRule->addAnotherWord) { //append another dictionary word
        tempWord.append(m_dicWords[nIndexOfX%m_nDicSize]);
        nIndexOfX=nIndexOfX / m_nDicSize;  //update the Index
      }
      else if ((tempRule->addAfter)||(tempRule->addBefore)) {  //insert a character
        if (tempRule->addType==1) {      //add a lowercase character
          tempChar=m_lower[nIndexOfX%m_lowerSize];
          nIndexOfX = nIndexOfX / m_lowerSize;
        }
        else if (tempRule->addType==2) {   //add an uppercase character
          tempChar=m_upper[nIndexOfX%m_upperSize];
          nIndexOfX = nIndexOfX / m_upperSize;
        }
        else if (tempRule->addType==3) {   //add a number
          tempChar = m_number[nIndexOfX%m_numberSize];
          nIndexOfX = nIndexOfX / m_numberSize;
        }
        else if (tempRule->addType==4) {   //add a special character
          tempChar =  m_special[nIndexOfX%m_specialSize];
          nIndexOfX = nIndexOfX / m_specialSize;
        }
        else {
           printf("ERROR WITH MANGLING INSERTION RULES, INVALID ADDTYPE SPECIFIED\n");
        }
        //---Now actually deal with the insertion-----------//
        if (tempRule->addAfter) {
          tempWord.append(1,tempChar);
        }
        else if (tempRule->addBefore) {
          tempInsertBefore.append(1,tempChar);  //initilize the insert before info
          canInsertBefore=true;    
        }      
      }
      else if (tempRule->doNothing) {  //NOOP operation
      }
      else if (tempRule->replaceChar) {   //replace a character
        //--Handled at the start of the rule, When optimizing this later we can remove these rule parts.
        //--removing this rule part should have no affect on previously generated tables
        //--Leaving this here for now for debugging purposes
//        doReplaceChar(&tempWord, tempRule->toReplace,tempRule->replaceWith); 
      }
      else {
        printf("Error with mangling rule.  That option is not supported at this time, Index Value=%s\n",uint64tostr(m_nIndex).c_str());
      }
      tempRule=tempRule->next;
    }
//    printf("string=%s\n",tempWord.c_str());
    if (canInsertBefore) {   //need to finally insert characters before your guess
      tempWord.insert(0,tempInsertBefore);
    }

    strncpy((char*)m_Plain,tempWord.c_str(),MAX_PLAIN_LEN);
    m_nPlainLen=tempWord.size();
  }   
}

void CChainWalkContext::t_IndexToPlain(threadType *passData) {
  int i;
  int j;
  uint64 tempIndex;
  ruleType *tempRule;
  string tempWord; //used to hold the plaintext word while it is being mangled
  char tempChar;   //used to hold the character to insert
  string tempInsertBefore;  //Used to insert a value before the dictionary word, (added so the insertions go in order)
  uint64 nIndexOfX;
  bool canInsertBefore;  //if there is a value to be inserted before the word
  if (!m_isDictionary) {
    for (i = m_nPlainLenMax - 1; i >= m_nPlainLenMin - 1; i--) {
      if (passData->t_nIndex >= m_nPlainSpaceUpToX[i]) {
        passData->t_nPlainLen = i + 1;
	break;
      }
    }

    nIndexOfX = passData->t_nIndex - m_nPlainSpaceUpToX[passData->t_nPlainLen - 1];
    /*
    // Slow version
    for (i = passData->t_nPlainLen - 1; i >= 0; i--) {
      passData->t_Plain[i] = m_PlainCharset[nIndexOfX % m_nPlainCharsetLen];
      nIndexOfX /= m_nPlainCharsetLen; 
    }
    */

    // Fast version
    for (i = passData->t_nPlainLen - 1; i >= 0; i--) {
#ifdef _WIN32
      if (nIndexOfX < 0x100000000I64)
        break;
#else
      if (nIndexOfX < 0x100000000llu)
	break;
#endif

      passData->t_Plain[i] = m_PlainCharset[nIndexOfX % m_nPlainCharsetLen];
      nIndexOfX /= m_nPlainCharsetLen;
    }
    unsigned int nIndexOfX32 = (unsigned int)nIndexOfX;
    for (; i >= 0; i--) {

      unsigned int nPlainCharsetLen = m_nPlainCharsetLen;
      unsigned int nTemp;
#ifdef _WIN32
      __asm {
		mov eax, nIndexOfX32
		xor edx, edx
		div nPlainCharsetLen
		mov nIndexOfX32, eax
		mov nTemp, edx
      }
#else
      __asm__ __volatile__ (	"mov %2, %%eax;"
		"xor %%edx, %%edx;"
		"divl %3;"
		"mov %%eax, %0;"
		"mov %%edx, %1;"
		: "=m"(nIndexOfX32), "=m"(nTemp)
		: "m"(nIndexOfX32), "m"(nPlainCharsetLen)
		: "%eax", "%edx"
		);
#endif
      passData->t_Plain[i] = m_PlainCharset[nTemp];
    }
  }
  else {  //-----Doing a dictionary based attack----------------//
    i=0;
    while ((i<m_nRuleSize)&&(passData->t_nIndex>m_end[i])) {  //first find the right rule to apply
      i++;
    }
    if (i==m_nRuleSize) {
      printf("ERROR INDEX IS OUT OF RANGE, index value=%d, maxRule=%d\n",passData->t_nIndex,m_nRuleSize);
      i--;
    }
    tempRule =&m_rules[i];
    nIndexOfX=passData->t_nIndex-m_start[i];
    //------First find the dictionary word to use and do any letter replacement----------//
    if (tempRule->replaceRule==NULL) { //no replacement
      tempWord=m_dicWords[nIndexOfX%m_nDicSize];
      nIndexOfX=nIndexOfX / m_nDicSize;  //update the Index
    }
    else {   //replacement rule
      tempWord=tempRule->replaceRule->dic[nIndexOfX%tempRule->replaceRule->numWords][0];
      for (i=0;i<tempRule->replaceRule->numReplace;i++) {
        if (tempRule->replaceRule->fromReplace[i]!=">") {
          doReplaceChar(&tempWord, tempRule->replaceRule->fromReplace[i],tempRule->replaceRule->toReplace[i]);
        }
      }    
      nIndexOfX=nIndexOfX / tempRule->replaceRule->numWords;
    }


    tempInsertBefore.clear();  //initilize the insert before info
    canInsertBefore=false;

    while (tempRule!=NULL) {   //while there are still rule parts to process
      if (tempRule->upperFirst) { //uppercase the first letter
        upperCase(&tempWord[0]);
      }
      else if (tempRule->upperAll) {   //uppercase all the letters
        for (j=0;j<tempWord.size();j++) {
          upperCase(&tempWord[j]);
        }
      }
      else if (tempRule->lowerAll) {     //lowercase all the letters
        for (j=0;j<tempWord.size();j++) {
          lowerCase(&tempWord[j]);
        }
      }
      else if (tempRule->upperLast) { //uppercase the last letter
        upperCase(&tempWord[tempWord.size()-1]);
      }
      else if (tempRule->repeat) {    //repeat the word, aka passwordpassword
        string addString = tempWord;   //using this so the append operation will work correctly, aka can't append a string to itself
        tempWord.append(addString);
      }
      else if (tempRule->addAnotherWord) { //append another dictionary word
        tempWord.append(m_dicWords[nIndexOfX%m_nDicSize]);
        nIndexOfX=nIndexOfX / m_nDicSize;  //update the Index
      }
      else if ((tempRule->addAfter)||(tempRule->addBefore)) {  //insert a character
        if (tempRule->addType==1) {      //add a lowercase character
          tempChar=m_lower[nIndexOfX%m_lowerSize];
          nIndexOfX = nIndexOfX / m_lowerSize;
        }
        else if (tempRule->addType==2) {   //add an uppercase character
          tempChar=m_upper[nIndexOfX%m_upperSize];
          nIndexOfX = nIndexOfX / m_upperSize;
        }
        else if (tempRule->addType==3) {   //add a number
          tempChar = m_number[nIndexOfX%m_numberSize];
          nIndexOfX = nIndexOfX / m_numberSize;
        }
        else if (tempRule->addType==4) {   //add a special character
          tempChar =  m_special[nIndexOfX%m_specialSize];
          nIndexOfX = nIndexOfX / m_specialSize;
        }
        else {
           printf("ERROR WITH MANGLING INSERTION RULES, INVALID ADDTYPE SPECIFIED\n");
        }
        //---Now actually deal with the insertion-----------//
        if (tempRule->addAfter) {
          tempWord.append(1,tempChar);
        }
        else if (tempRule->addBefore) {
          tempInsertBefore.append(1,tempChar);  //initilize the insert before info
          canInsertBefore=true;    
        }      
      }
      else if (tempRule->doNothing) {  //NOOP operation
      }
      else if (tempRule->replaceChar) {   //replace a character
        //--Handled at the start of the rule, When optimizing this later we can remove these rule parts.
//        doReplaceChar(&tempWord, tempRule->toReplace,tempRule->replaceWith); 
      }
      else {
        printf("Error with mangling rule.  That option is not supported at this time, Index Value=%s\n",uint64tostr(passData->t_nIndex).c_str());
      }
      tempRule=tempRule->next;
    }
    if (canInsertBefore) {   //need to finally insert characters before your guess
      tempWord.insert(0,tempInsertBefore);
    }
    strncpy((char*)passData->t_Plain,tempWord.c_str(),MAX_PLAIN_LEN);
    passData->t_nPlainLen=tempWord.size();
  }   
}


////////////////////////////////////////////////////////////////////////
//This function replaces all occurances of "toReplace" with "replaceWith"
//If "toReplace" does not occur in the input, append the dummy string at the end
//to avoid collisions with other mangling rules.  yah it sucks, but the only
//way to avoid that, (that I can think of) is to sort the dictionary up into different sets, each which
//only contains the corresponding mangling rule
//
//Note with the modification to how I handle the replacement dictionary the dummy string should no longer
//be needed, but I left it in for debugging purposes because god knows I've had bugs in my code before
//
int CChainWalkContext::doReplaceChar(string *input, string fromReplace, string replaceWith) {
//Note, currently only deals with one letter replacements
  char fromTemp;
  char toTemp;
  char tempChar;
  bool didReplace=false;
  int i;
  int length;

  fromTemp=fromReplace[0];
  toTemp=replaceWith[0];

  length=input->size();
  for (i=0;i<length;i++) {
    tempChar=input->at(i);
    if (tempChar==fromTemp) {
      didReplace=true;
      input->replace(i,1,1,toTemp);
    }
  }
  if (!didReplace) { //add the dummy string since no replacement happened
    char appendValue[6];
    appendValue[0]='-';
    appendValue[1]='!';
    appendValue[2]='!';
    appendValue[3]=fromTemp;
    appendValue[4]=toTemp;
    appendValue[5]='\0';
    input->append(appendValue,5);
    printf("ERROR with Replacement dictionary\n");
  }


  return 0;
}


////////////////////////////////////////////////////////////////////
//Yes this function looks pretty pointless, but I'm abstracting it
//so I can easily add support for non-English languages in the future
int CChainWalkContext::upperCase(char *input) {
  if (islower(input[0])) {
    input[0]=toupper(input[0]);
  }
  return 0;
}

////////////////////////////////////////////////////////////////////
//Yes this function looks pretty pointless, but I'm abstracting it
//so I can easily add support for non-English languages in the future
int CChainWalkContext::lowerCase(char *input) {
  if (isupper(input[0])) {
    input[0]=tolower(input[0]);
  }
  return 0;
}


void CChainWalkContext::PlainToHash()
{
//	  m_pHashRoutine(m_Plain, m_nPlainLen, m_Hash);
	m_pHashRoutine(m_Plain, m_nPlainLen, m_Hash, m_salt, m_saltLen);
}

void CChainWalkContext::t_PlainToHash(threadType *passData) {
//	m_pHashRoutine(passData->t_Plain, passData->t_nPlainLen,passData->t_Hash);
	m_pHashRoutine(passData->t_Plain, passData->t_nPlainLen,passData->t_Hash, m_salt, m_saltLen);
}


void CChainWalkContext::HashToIndex(int nPos)
{
	m_nIndex = (*(uint64*)m_Hash + m_nReduceOffset + nPos) % m_nPlainSpaceTotal;
}

void CChainWalkContext::t_HashToIndex(int nPos, threadType *passData) {
	passData->t_nIndex =(*(uint64*)passData->t_Hash + m_nReduceOffset + nPos) % m_nPlainSpaceTotal;
}

uint64 CChainWalkContext::GetIndex()
{
	return m_nIndex;
}

string CChainWalkContext::GetPlain()
{
	string sRet;
	int i;
	for (i = 0; i < m_nPlainLen; i++)
	{
		char c = m_Plain[i];
		if (c >= 32 && c <= 126)
			sRet += c;
		else
			sRet += '?';
	}
	
	return sRet;
}

string CChainWalkContext::GetBinary()
{
	return HexToStr(m_Plain, m_nPlainLen);
}

string CChainWalkContext::GetPlainBinary()
{
	string sRet;
	sRet += GetPlain();
	int i;
	for (i = 0; i < m_nPlainLenMax - m_nPlainLen; i++)
		sRet += ' ';

	sRet += "|";

	sRet += GetBinary();
	for (i = 0; i < m_nPlainLenMax - m_nPlainLen; i++)
		sRet += "  ";

	return sRet;
}

string CChainWalkContext::GetHash()
{
	return HexToStr(m_Hash, m_nHashLen);
}

bool CChainWalkContext::CheckHash(unsigned char* pHash)
{
	if (memcmp(m_Hash, pHash, m_nHashLen) == 0)
		return true;
	return false;
}
