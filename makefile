CC=g++
XFLAG =-lssl -lcrypto -lpthread -O3
all: drtgen rtdump rtsort drcrack rcalc_raw dr_rules

drtgen: Public.o ChainWalkContext.o HashAlgorithm.o HashRoutine.o RainbowTableGenerate.o md5.o md4.o 
	$(CC) Public.o ChainWalkContext.o HashAlgorithm.o HashRoutine.o RainbowTableGenerate.o md5.o md4.o $(XFLAG) -o drtgen

rtgen.o: Public.cpp ChainWalkContext.cpp HashAlgorithm.cpp HashRoutine.cpp RainbowTableGenerate.cpp md5.cpp md4.cpp
	$(CC) -c Public.cpp ChainWalkContext.cpp HashAlgorithm.cpp HashRoutine.cpp RainbowTableGenerate.cpp md5_go.c -O3 

rtdump:
	g++ Public.cpp ChainWalkContext.cpp HashAlgorithm.cpp HashRoutine.cpp RainbowTableDump.cpp md4.cpp md5.cpp  -lssl -lcrypto -o rtdump

rtsort:
	g++ Public.cpp RainbowTableSort.cpp -lcrypto -o rtsort

drcrack: Public.o ChainWalkContext.o HashAlgorithm.o HashRoutine.o HashSet.o MemoryPool.o ChainWalkSet.o CrackEngine.o RainbowCrack.o md5.o md4.o
	$(CC) Public.o ChainWalkContext.o HashAlgorithm.o HashRoutine.o HashSet.o MemoryPool.o ChainWalkSet.o CrackEngine.o RainbowCrack.o md5.o md4.o $(XFLAG) -o drcrack

rcrack.o:
	$(CC) -c Public.cpp ChainWalkContext.cpp HashAlgorithm.cpp HashRoutine.cpp HashSet.cpp MemoryPool.cpp ChainWalkSet.cpp CrackEngine.cpp RainbowCrack.cpp md5.cpp md4.cpp -O3

dr_rules: dr_rules.o
	$(CC) dr_rules.o $(XFLAG) -o dr_rules

dr_rules.o: dr_rules.c
	$(CC) -c dr_rules.c -O3

rcalc: rcalc.o
	$(CC) rcalc.o -o rcalc

rcalc_raw.o:
	$(CC) -c rcalc_raw.c



clean:
	rm -f drtgen
	rm -f rtdump
	rm -f rtsort
	rm -f drcrack
	rm -f *.o

removeHash:
	rm -f md5_*
