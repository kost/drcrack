/*
   RainbowCrack - a general propose implementation of Philippe Oechslin's faster time-memory trade-off technique.

   Copyright (C) Zhu Shuanglei <shuanglei@hotmail.com>

   Modifications made by Matt Weir <weir@cs.fsu.edu>
*/

#ifdef _WIN32
	#pragma warning(disable : 4786)
#endif

#ifdef _WIN32
	#include <windows.h>
#else
	#include <unistd.h>
#endif
#include <time.h>
#include "ChainWalkContext.h"
#include <string.h>
#include <pthread.h>


void *tGenerate(void *);
void *tBenchGen(void *);

#define BENCHSIZE 100000 //How many chains to generate when benchmarking
#define BENCHSTEPSIZE 10000 //How big each printout step should be
int curCount;
time_t t1;
int nRainbowChainLen;
int nRainbowChainCount;
FILE* file;
pthread_mutex_t mutex1=PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t mutex2=PTHREAD_MUTEX_INITIALIZER;
CChainWalkContext cwc;


void Usage()
{
	Logo();

	printf("usage: drtgen <options> \n");
	printf("-------------------------------------\n");
        printf("|Options For All Rainbow Table Types|\n");
        printf("-------------------------------------\n");
        printf("\t-file    <file name>    \t(REQUIRED):The rt filename to use, not required if using -bench\n");
        printf("\t-hash    <hash type>    \t(REQUIRED):The hash type to use\n");
	CHashRoutine hr;
	printf("\thash types supported: %s\n", hr.GetAllHashRoutineName().c_str());
        printf("\t-cLen    <chain length> \t(REQUIRED):The length of each chain, aka the compression used\n");
	printf("\t-cCount    <# of chains>  \t(REQUIRED):The number of chains, influences how big the table will be\n");
	printf("\t-bench                  \t(optional):benchmark how long the table will take to generate\n");
        printf("\t-index   <index value>  \t(optional):The index offset, only matters if you have multiple tables\n");
	printf("\t-threads <num threads>  \t(optional):The number of processors to use\n");
	printf("\t-salt    <salt value>   \t(optional):The salt value to use for the hash. Capitalization matters!\n");
	printf("\tIf no salt is specified, mscache=\"administrator\", oracle=\"SYS\"\n");

	printf("\n");
	printf("-------------------------------------\n");
	printf("|Options For Dictionary Based Tables|\n");
	printf("-------------------------------------\n");
	printf("\t-d                      \t(REQUIRED):Tell drtgen that this is a dictionary based attack\n");
	printf("\t-dic   <dictionary name>\t(REQUIRED):The name of the input dictionary to use\n");
        printf("\t-rules <rules file name>\t(REQURIED):The name of the word mangling rule file to use\n");

	printf("\n");
	printf("----------------------------------------\n");
	printf("|Options For Traditional Rainbow Tables|\n");
	printf("----------------------------------------\n");
	printf("\t-charset <charset name> \t(REQUIRED):The character set to use, a list can be found in charset.txt\n");
	printf("\tuse \"byte\" to specify all 256 characters as the charset of the plaintext\n");
	printf("\t-lmin    <minimum size> \t(REQUIRED):The minimum sized password to try and bruteforce\n");
	printf("\t-lmax    <maximum size> \t(REQUIRED):The maximum sized password to try and bruteforce\n");


	printf("\n");
	printf("-----------\n");
	printf("|Examples |\n");
	printf("-----------\n");
	printf("\tBasic Dictionary Based Attack\n");
	printf("\t./drtgen -d -dic inputdic.txt -rules manglingrules.txt -hash ntlm -cLen 2600 -cCount 500000 -file basic_ntlm_table\n");
	printf("\tBasic Salted Dictionary Based Attack\n");
	printf("\t./drtgen -d -dic inputdic.txt -rules manglingrules.txt -hash mscache -salt administrator -cCount 2600 -cNum 500000 -file basic_ntlm_table\n");
	printf("\tMulti-threaded Dictionary Based Attack\n");
	printf("\t./drtgen -d -dic inputdic.txt -rules manglingrules.txt -hash ntlm -p 4 -cLen 2600 -cCount 500000 -file basic_ntlm_table\n");
	printf("\tBenchmarking a Dictionary Based Attack -Note: Will generally underestimate time due to the fact it doesn't write to disk\n");
	printf("\t./drtgen -d -dic inputdic.txt -rules manglingrules.txt -hash ntlm -cLen 2600 -cCount 500000 -bench\n");
	printf("\tTraditional Rainbow Table Generation\n");
	printf("\t./drtgen -d -charset loweralpha-numeric -lmin 0 -lmax 7 -hash ntlm -cLen 2600 -cCount 500000 -file basic_ntlm_table\n");
	printf("\n\n");
}

void Bench(int numThreads) {
	time_t startTime;
	time_t endTime;
        double fTime;
	int nHours;
	int nMinutes;
	int nSeconds;
	int i;
	pthread_t thread1[MAXTHREADS];

	// Generate rainbow table
        printf("benchmarking...\n");
        time(&t1);
	startTime=t1;
        int tmp[MAXTHREADS];
        curCount=0;
        for (i=0;i<numThreads;i++) {
          tmp[i] = i;
          if ((pthread_create(&thread1[i], NULL, tBenchGen, (void*)&tmp[i])) != 0) {
            printf("thread creation failed. %d\n", i);
          }
        }
        for (i=0;i<numThreads;i++) {
          pthread_join(thread1[i], NULL);
        }
	time(&endTime);
	fTime = difftime(endTime,startTime);
	fTime = fTime * (nRainbowChainCount/BENCHSIZE); //Find out how long to generate the entire table
	nHours   = (int)fTime/3600;
	nMinutes = ((int)fTime/60)%60;
        nSeconds = (int)fTime%60;
	printf("To generate a table of size %d using %d thread", nRainbowChainCount, numThreads);
	if (numThreads==1) {
	  printf(" ");
	}
	else {
	  printf("s ");
	}
	printf("would take %d ",nHours); 
	if (nHours==1) {
	  printf("Hour ");
	}
	else {
	  printf("Hours ");
	}
	printf("%d ",nMinutes);
	if (nMinutes==1) {
	  printf("Minute ");
	}
	else {
	  printf("Minutes ");
	}
	printf("and %d ",nSeconds);
	if (nSeconds==1) {
	  printf("Second\n");
	}
	else {
	  printf("Seconds\n");
	}
}

int main(int argc, char* argv[]) {
	int nIsDictionary;
	int isBench;
	string sHashRoutineName;
        string sCharsetName;
        int nPlainLenMin;
        int nPlainLenMax;
        int nRainbowTableIndex;
        string sDicName;
        string sRuleName;
        string sFileTitleSuffix;
        string sSalt;
        char configFileName[256];
        char szFileName[256];
        FILE *configFile;
        pthread_t thread1[MAXTHREADS];
        int numThreads;
	int i;

        //initilize the values
        i=1;
        nIsDictionary=0;
        isBench=0;
        nPlainLenMin=-1;
        nPlainLenMax=-1;
        sHashRoutineName = "-1";
        sCharsetName = "-1";
        nRainbowTableIndex = 0;
        nRainbowChainLen     = -1;
        nRainbowChainCount   = -1;
        sFileTitleSuffix  = "-1";
        numThreads=1;
        sDicName = "-1";
        sRuleName = "-1";
        sSalt = "-1";

        while (i<argc) {
          if (strcmp(argv[i],"-d")==0) {
            nIsDictionary=1;
            i++;
          }
          else if (strcmp(argv[i],"-lmin")==0) {
            if (i<argc) {
              nPlainLenMin=atoi(argv[i+1]);
              i=i+2;
            }
            else {
              printf("Error, you need to enter a value for -lmin");
              return false;
            }
          }
          else if (strcmp(argv[i],"-lmax")==0) {
            if (i<argc) {
              nPlainLenMax=atoi(argv[i+1]);
              i=i+2;
            }
            else {
              printf("Error, you need to enter a value for -lmax");
              return -1;
            }
          }
          else if (strcmp(argv[i],"-hash")==0) {
            if (i<argc) {
              sHashRoutineName=argv[i+1];
              i=i+2; 
            }
            else {
              printf("Error, you need to enter a value for -hash");
              return -1;
            }
          }
          else if (strcmp(argv[i],"-charset")==0) {
            if (i<argc) {
              sCharsetName=argv[i+1];
              i=i+2;
            }
            else {
              printf("Error, you need to enter a value for -charset");
              return -1;
            }
          }
          else if (strcmp(argv[i],"-index")==0) {
            if (i<argc) {
              nRainbowTableIndex=atoi(argv[i+1]);
              i=i+2;
            }
            else {
              printf("Error, you need to enter a value for -index");
              return -1;
            }
          } 
          else if ((strcmp(argv[i],"-cLen")==0)||(strcmp(argv[i],"-clen")==0)) {
            if (i<argc) {
              nRainbowChainLen=atoi(argv[i+1]);
              i=i+2;
            }
            else {
              printf("Error, you need to enter a value for -cLen");
              return -1;
            }
          }
          else if ((strcmp(argv[i],"-cCount")==0)||(strcmp(argv[i],"-ccount")==0)) {
            if (i<argc) {
              nRainbowChainCount=atoi(argv[i+1]);
              i=i+2;
            }
            else {
              printf("Error, you need to enter a value for -cCount");
              return -1;
            }
          }
          else if (strcmp(argv[i],"-file")==0) {
            if (i<argc) {
              sFileTitleSuffix=argv[i+1];
              i=i+2;
            }
            else {
              printf("Error, you need to enter a value for -file");
              return -1;
            }
          }
          else if ((strcmp(argv[i],"-threads")==0)||(strcmp(argv[i],"-thread")==0)) {
            if (i<argc) {
              numThreads=atoi(argv[i+1]);
              i=i+2;
            }
            else {
              printf("Error, you need to enter a value for -threads");
              return -1;
            }
          }
          else if (strcmp(argv[i],"-dic")==0) {
            if (i<argc) {
              sDicName=argv[i+1];
              i=i+2;
            }
            else {
              printf("Error, you need to enter a value for -dic");
              return -1;
            }
          }
          else if ((strcmp(argv[i],"-rule")==0)||(strcmp(argv[i],"-rules")==0)) {
            if (i<argc) {
              sRuleName=argv[i+1];
              i=i+2;
            }
            else {
              printf("Error, you need to enter a value for -rules");
              return -1;
            }
          }
          else if (strcmp(argv[i],"-salt")==0) {
            if (i<argc) {
              sSalt=argv[i+1];
              i=i+2;
            }
            else {
              printf("Error, you need to enter a value for -salt");
              return -1;
            }
          }
          else if (strcmp(argv[i],"-bench")==0) {
	    isBench=1;
	    i++;
	  }
          else {
            printf("Invalid command line value (%s)\n",argv[i]);
            Usage();
            return -1;    
          }
        }


        //Check to see if all the required values were entered
        if ((nRainbowChainLen<1)||(nRainbowChainCount<1)||(sHashRoutineName[0]=='-')||((sFileTitleSuffix[0]=='-')&&(isBench==0))) {
          printf("Missing Essential Setting\n");
          Usage();
	  return 0;
          
        }
        if (nIsDictionary==1) {
          if ((sDicName[0]=='-')||(sRuleName[0]=='-')) {
            printf("Missing Essential Setting for Dictionary Based Tables\n");
            Usage();
            return 0;
          }
        }
        else {  //A traditional rainbow table
          if ((nPlainLenMin<1)||(nPlainLenMax<1)||(sCharsetName[0]=='-')) {
            printf("Missing Essential Setting for Traditional Rainbow Table\n");
            Usage();
            return 0;
          }
        } 
        if (sSalt[0]=='-') {
          if (sHashRoutineName.compare("mscache")==0) {
            sSalt="administrator";
          }
          else if (sHashRoutineName.compare("oracle")==0) {
            sSalt="SYS";
          }
        }
        CChainWalkContext::SetSalt(sSalt); 
	// nRainbowChainCount check
	if (nRainbowChainCount >= 134217728)
	{
		printf("this will generate a table larger than 2GB, which is not supported\n");
		printf("please use a smaller rainbow_chain_count(less than 134217728)\n");
		return 0;
	}

	// Setup CChainWalkContext
	if (!CChainWalkContext::SetHashRoutine(sHashRoutineName))
	{
		printf("hash routine %s not supported\n", sHashRoutineName.c_str());
		return 0;
	}
        if (nIsDictionary==0) {
	  if (!CChainWalkContext::SetPlainCharset(sCharsetName, nPlainLenMin, nPlainLenMax)) {
		return 0;
          }
        }
        else { //if doing a dictionary based attack
          if (!CChainWalkContext::SetManglingRules(sRuleName)) {
            return 0;
          }
          if (!CChainWalkContext::SetDictionary(sDicName)) {
            return 0;
          }
          if (!CChainWalkContext::SetRuleSize()) {
            return 0;
          }
        }
	if (!CChainWalkContext::SetRainbowTableIndex(nRainbowTableIndex))
	{
		printf("invalid rainbow table index %d\n", nRainbowTableIndex);
		return 0;
	}
	CChainWalkContext::Dump();

	// Low priority
#ifdef _WIN32
	SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_IDLE);
#else
	nice(19);
#endif
	if (isBench!=0) { //benchmarking
          Bench(numThreads);
          return 0;
        }	
	// FileName
        if (nIsDictionary==0) {
	  snprintf(szFileName,255, "%s_%s#%d-%d_%d_%dx%d_%s.rt", sHashRoutineName.c_str(),
		sCharsetName.c_str(),nPlainLenMin,nPlainLenMax,nRainbowTableIndex,nRainbowChainLen,nRainbowChainCount,sFileTitleSuffix.c_str());
        }
        else { //if a dictionary based attack
          snprintf(szFileName,255,"%s.rt",sFileTitleSuffix.c_str());
          snprintf(configFileName,255,"%s.cfg",sFileTitleSuffix.c_str());
          configFile=fopen(configFileName,"w");
          if (configFile==NULL) {
            printf("Could not create the config file.  Exiting\n");
            return -1;
          }
          fprintf(configFile,"<Type>dictionary\n");
          fprintf(configFile,"<Version>1.03\n");
          fprintf(configFile,"<Hash>%s\n",sHashRoutineName.c_str());
          fprintf(configFile,"<Salt>%s\n",sSalt.c_str());
          fprintf(configFile,"<Index>%d\n",nRainbowTableIndex);
          fprintf(configFile,"<ChainLen>%d\n",nRainbowChainLen);
          fprintf(configFile,"<ChainCount>%d\n",nRainbowChainCount);
          fprintf(configFile,"<RainbowTable>%s.rt\n",sFileTitleSuffix.c_str());
          fprintf(configFile,"<Dictionary>%s\n",sDicName.c_str());
          fprintf(configFile,"<ManglingRules>%s\n",sRuleName.c_str());
          fclose(configFile);
        } 
	// Open file
	fclose(fopen(szFileName, "a"));
	file = fopen(szFileName, "r+b");
	if (file == NULL)
	{
		printf("failed to create %s\n", szFileName);
		return 0;
	}

	// Check existing chains
	unsigned int nDataLen = GetFileLen(file);
	nDataLen = nDataLen / 16 * 16;
	if (nDataLen == nRainbowChainCount * 16)
	{
		printf("precomputation of this rainbow table already finished\n");
		fclose(file);
		return 0;
	}
	if (nDataLen > 0)
		printf("continuing from interrupted precomputation...\n");
	fseek(file, nDataLen, SEEK_SET);

	// Generate rainbow table
	printf("generating...\n");
	time(&t1);
        int tmp[MAXTHREADS];
        curCount=nDataLen / 16;
        for (i=0;i<numThreads;i++) {
          tmp[i] = i;
          if ((pthread_create(&thread1[i], NULL, tGenerate, (void*)&tmp[i])) != 0) {
	    printf("thread creation failed. %d\n", i);
          }         
        }
        for (i=0;i<numThreads;i++) {
          pthread_join(thread1[i], NULL);
        }
	// Close
	fclose(file);

	return 0;
}

void *tGenerate(void *arg) {
  int i;
  int me;
  uint64 nIndex;
  uint64 start_nIndex;
  int nPos;
  time_t t2;
  double nTime;
  int nMinutes;
  int nSeconds;
  bool done=false;
  me = *(int *)arg;
  threadType *passData;
  passData=new threadType;
  
  while (!done) {
    pthread_mutex_lock(&mutex1);
    if (curCount < nRainbowChainCount) {
      if ((curCount + 1) % 100000 == 0 || curCount + 1 == nRainbowChainCount) {
        time(&t2);
        nTime = difftime(t2,t1);
        nMinutes = (int)nTime/60;
        nSeconds = (int)nTime%60;
        printf("%d of %d rainbow chains generated (%d m %d s)\n", curCount + 1,nRainbowChainCount,nMinutes, nSeconds);
        time(&t1);
      }
      curCount++;
      pthread_mutex_unlock(&mutex1);

      cwc.t_GenerateRandomIndex(passData);
      nIndex = passData->t_nIndex;
      start_nIndex=nIndex;

      for (nPos = 0; nPos < nRainbowChainLen - 1; nPos++) {
        cwc.t_IndexToPlain(passData);
        cwc.t_PlainToHash(passData);
        cwc.t_HashToIndex(nPos,passData);
      }

      nIndex = passData->t_nIndex;
      pthread_mutex_lock(&mutex2);
      if (fwrite(&start_nIndex, 1, 8, file) != 8) {
        printf("disk write fail\n");
        pthread_mutex_unlock(&mutex2);
        return NULL;
      }
      if (fwrite(&nIndex, 1, 8, file) != 8) {
        printf("disk write fail\n");
        pthread_mutex_unlock(&mutex2);
        return NULL;
      }
      pthread_mutex_unlock(&mutex2);

    }
    else {   //done with work
      done=true;
      pthread_mutex_unlock(&mutex1);
    }
  }
  return NULL;
}


///////////////////////////////////////////////////////////////////////////////////////////////
//Used to benchmark how long creating a table using multiple threads will take
void *tBenchGen(void *arg) {
  int i;
  int me;
  uint64 nIndex;
  uint64 start_nIndex;
  int nPos;
  time_t t2;
  double nTime;
  int nMinutes;
  int nSeconds;
  bool done=false;
  me = *(int *)arg;
  threadType *passData;
  passData=new threadType;

  while (!done) {
    pthread_mutex_lock(&mutex1);
    if (curCount < BENCHSIZE) {
      if ((curCount + 1) % (BENCHSTEPSIZE) == 0 || curCount + 1 == BENCHSIZE) {
        time(&t2);
        nTime = difftime(t2,t1);
        nMinutes = (int)nTime/60;
        nSeconds = (int)nTime%60;
        printf("%d of %d rainbow chains generated (%d m %d s)\n", curCount + 1,BENCHSIZE,nMinutes, nSeconds);
        time(&t1);
      }
      curCount++;
      pthread_mutex_unlock(&mutex1);

      cwc.t_GenerateRandomIndex(passData);
      nIndex = passData->t_nIndex;
      start_nIndex=nIndex;

      for (nPos = 0; nPos < nRainbowChainLen - 1; nPos++) {
        cwc.t_IndexToPlain(passData);
        cwc.t_PlainToHash(passData);
        cwc.t_HashToIndex(nPos,passData);
      }
      nIndex = passData->t_nIndex;
    }
    else {   //done with work
      done=true;
      pthread_mutex_unlock(&mutex1);
    }
  }
  return NULL;
}

