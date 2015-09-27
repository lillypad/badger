//--------------------------//
//---------BADGER-----------//
//-BY: ARC NETWORK SECURITY-//
//--------------------------//

//Includes
#include <stdio.h>
#include <windows.h>
#include <libgen.h>
#include "documentation.h"

//Defines
#define WINDOWS
#ifdef WINDOWS
#define MAX_PATH 260
#endif
#ifdef LINUX
#define MAX_PATH 255
#endif

//Boolean Operations
typedef int bool;
#define true 1 
#define false 0 


void printAddress(char fileName[MAX_PATH], char functionName[MAX_PATH]){
	printf("0x%x", GetProcAddress(LoadLibraryA(fileName), functionName));
}

int getFileSize(FILE *inputFile){
	int fileSize;
	fseek(inputFile, 0L, SEEK_END);
	fileSize = ftell(inputFile);
	return fileSize;
}

int main(int argc, char *argv[]){
	
	if (argc < 2){
		printf("ERROR: Not Enough Arguments.\n");
		help();
		return 1;
	}
	
	//Handler For Argument Order
	int argEnum, argList, argASLRCheck, argEnableDep, argDisableDep, argLib, argHelp, argAbout, argAlphaRef;
	bool boolList = false;
	int c = 0;
	for(c = 0; c <= argc-1; c++){
		if(strcmp(argv[c], "--list") == 0){
			boolList = true;
			argList = c;
		}
	}
	
	bool boolEnum = false;
	c = 0;
	for(c = 0; c <= argc-1; c++){
		if(strcmp(argv[c], "--enum") == 0){
			boolEnum = true;
			argEnum = c;
		}
	}
	
	bool boolASLRCheck = false;
	c = 0;
	for(c = 0; c <= argc-1; c++){
		if(strcmp(argv[c], "--aslr-check") == 0){
			boolASLRCheck = true;
			argASLRCheck = c;
		}
	}
	
	bool boolEnableDep = false;
	c = 0;
	for(c = 0; c <= argc-1; c++){
		if(strcmp(argv[c], "--enable-dep") == 0){
			boolEnableDep = true;
			argEnableDep = c;
		}
	}
	
	bool boolDisableDep = false;
	c = 0;
	for(c = 0; c <= argc-1; c++){
		if(strcmp(argv[c], "--disable-dep") == 0){
			boolDisableDep = true;
			argDisableDep = c;
		}
	}
	
	bool boolLib = false;
	c = 0;
	for(c = 0; c <= argc-1; c++){
		if(strcmp(argv[c], "--lib") == 0){
			boolLib = true;
			argLib = c;
		}
	}
	
	bool boolHelp = false;
	c = 0;
	for(c = 0; c <= argc-1; c++){
		if( (strcmp(argv[c], "--help") == 0) || (strcmp(argv[c], "-h") == 0) ){
			boolHelp = true;
			argHelp = c;
		}
	}
	
	bool boolAbout = false;
	c = 0;
	for(c = 0; c <= argc-1; c++){
		if(strcmp(argv[c], "--about") == 0){
			boolAbout = true;
			argAbout = c;
		}
	}
	
	bool boolAlphaRef = false;
	c = 0;
	for(c = 0; c <= argc-1; c++){
		if(strcmp(argv[c], "--alphanum-ref") == 0){
			boolAlphaRef = true;
			argAlphaRef = c;
		}
	}
	//End Handler for Argument Order
	
	//Start Help
	if(boolHelp == true){
		if( (strcmp(argv[argHelp], "--help") == 0) || (strcmp(argv[argHelp], "-h") == 0) ){
			help();
			if(boolAbout == true || boolASLRCheck == true || boolDisableDep == true || boolEnableDep == true || boolEnum == true || boolList == true || boolLib == true || boolAlphaRef == true){
				printf("\n");
			}
		}
	}
	//End Help
	
	//Start About
	if(boolAbout == true){
		if(strcmp(argv[argAbout], "--about") == 0){
			about();
			if(boolASLRCheck == true || boolDisableDep == true || boolEnableDep == true || boolEnum == true || boolList == true || boolLib == true || boolAlphaRef == true){
				printf("\n");
			}
		}
	}
	//End About
	
	if(boolAlphaRef == true){
		if(strcmp(argv[argAlphaRef], "--alphanum-ref") == 0){
			alphaNumericRef();
			if(boolASLRCheck == true || boolDisableDep == true || boolEnum == true || boolList == true || boolLib == true || boolEnableDep == true){
				printf("\n");
			}
		}
	}
	
	//Enable DEP Requires Administrator Rights
	if (boolEnableDep == true){
		if (strcmp(argv[argEnableDep], "--enable-dep") == 0){
			int stderror = system("bcdedit.exe /set {current} nx AlwaysOn");
			if(stderror == 1){
				printf("Please Run --enable-dep as Administrator.");
			}
			if(boolASLRCheck == true || boolDisableDep == true || boolEnum == true || boolList == true || boolLib == true){
				printf("\n");
			}
		}
	}
	
	//Disable DEP Requires Administrator Rights
	if (boolDisableDep == true){
		if (strcmp(argv[argDisableDep], "--disable-dep") == 0){
			int stderror = system("bcdedit.exe /set {current} nx AlwaysOff");
			if(stderror == 1){
				printf("Please Run --disable-dep as Administrator.");
			}
			if(boolASLRCheck == true || boolEnum == true || boolList == true || boolLib == true){
				printf("\n");
			}
		}
	}
	
	//ASLR Checker
	if (boolASLRCheck == true){
		if (strcmp(argv[argASLRCheck], "--aslr-check") == 0){
			register int esp asm("esp");
			register int rsp asm("rsp");
			printf("Run Multiple Time if Changes ASLR is Enabled.\n");
			printf("x86 ESP: 0x%x\n", esp);
			printf("x64 RSP: 0x%x", rsp);
			if(boolEnum == true || boolList == true || boolLib == true){
				printf("\n");
			}
		}
	}
	//End ASLR Checker
	
	//Start Enumerate Specific Function with --lib
	if (boolLib == true){
		if(strcmp(argv[argLib], "--lib") == 0){
			
			unsigned int api_addr = 0;
			if(argc <= argLib+1){
				printf("Please include library file.");
				return 1;
			}
			if (GetProcAddress(LoadLibraryA(argv[argLib+1]), argv[argLib+2]) == 0){
				printf("Please specify correct function name.");
				return 1;
			}
			unsigned char libFunctionName[MAX_PATH];
			strcpy(libFunctionName, argv[argLib+2]);
			printf("Function Name: %s\n", libFunctionName);
			
			printAddress(argv[argLib+1], argv[argLib+2]);
			if(boolEnum == true || boolList == true){
				printf("\n");
			}
			//return 0;
		}
	}
	
	//If --list is supplied without --enum
	if(boolList == true && boolEnum == false){
		printf("To use list you must use --enum as well.");
	}
	
	//Start Variable Initialization
	FILE *infile;
	long int i, j, k;
	long int rvaBuffInt, rawdataPtrBuffInt, rvaOffset, exptblBuffInt, exptblInt, namervaBuffInt, namervaOffset, numFunctions, namesOffset;
	long int fileSize;
	unsigned char cmpPE[2];
	unsigned char cmpBUFF[16];
	unsigned char dllChar[2];
	unsigned char actbaseBuff[3];
	unsigned char numfuncBuff[3];
	unsigned char namervaBuff[3];
	unsigned char exptblBuff[3];
	unsigned char rvaBuff[3];
	unsigned char rawdataPtrBuff[3];
	unsigned char namesdllBuff[MAX_PATH];
	unsigned char singleByte[1];
	unsigned char functionName[MAX_PATH];
	long int functNameInt = 0;
	long int functCount = 0;
	
	bool namestblBOOL = false;
	int numSections = 0;
	int totalSections;
	long int rvaINT, rawdataINT, rvaOFFSET, exptblINT, rvavsrawINT, namervaINT, textOFFSET, dataOFFSET, rdataOFFSET, bssOFFSET, edataOFFSET, idataOFFSET, crtOFFSET, tlsOFFSET, rsrcOFFSET, relocOFFSET, namestblINT, namestblOFFSET;
	unsigned char numSectionsBUFF[1];
	unsigned char rvaBUFF[3];
	unsigned char rawdataBUFF[3];
	unsigned char exptblBUFF[3];
	unsigned char namervatblBUFF[3];
	unsigned char namestblBUFF[3];
	unsigned char dllBUFF[MAX_PATH];
	
	//End Variable Initialization
	
	if (boolEnum == true){
	
		if(strcmp(argv[argEnum], "--enum") == 0){
			if(argc < 3){
				printf("Please include library file.");
				return 1;
			}
			infile = fopen(argv[argEnum+1], "rb");
			if (!infile){
				printf("Unable to read or find file provided.");
				return 1;
			}
			char fileName[MAX_PATH];
			char filePath[MAX_PATH];
			strcpy(filePath, argv[argEnum+1]);
			strcpy(fileName, basename(argv[argEnum+1]));
			printf("File Name: %s\n", fileName);
			printf("File Path: %s\n", filePath);
			fileSize = getFileSize(infile);
			printf("File Size: %d bytes\n", fileSize);
			
			//File data before sections
			for(i = 0; i <= fileSize; i++){
				fseek(infile, i, SEEK_SET);
				fread(cmpPE, sizeof(cmpPE)+1, 1, infile);
				if (cmpPE[0] == 'P' && cmpPE[1] == 'E'){
					printf("PE Header Offset: 0x%x\n", i);
					i = i + 52;
					fseek(infile, i, SEEK_SET);
					fread(actbaseBuff, sizeof(actbaseBuff)+1, 1,infile);
					printf("Preferred Base: 0x%02x%02x%02x%02x\n", actbaseBuff[3], actbaseBuff[2], actbaseBuff[1], actbaseBuff[0]);
					i = i + 42;
					fseek(infile, i, SEEK_SET);
					fread(dllChar, sizeof(dllChar)+1, 1, infile);
					printf("DLL Characteristics: 0x%02x%02x\n", dllChar[1], dllChar[0]);
					if (dllChar[1] == '\x01'){
						printf("DEP is Enabled\n");
					}
					else {
						printf("DEP is Disabled\n");
					}
					if (dllChar[0] == '\x40'){
						printf("ASLR is Enabled (Virtual Address may Change on Load)\n");
					}
					else {
						printf("ASLR is Disabled\n");
					}
					i = i + 24+2;
					fseek(infile, i, SEEK_SET);
					fread(exptblBuff, sizeof(exptblBuff)+1, 1, infile);
					exptblBuffInt = exptblBuff[0] | (exptblBuff[1]<<8) | (exptblBuff[2]<<16) | (exptblBuff[3]<<24);
					printf("Export Table RVA: 0x%02x%02x%02x%02x\n", exptblBuff[3], exptblBuff[2], exptblBuff[1], exptblBuff[0]);
					break;
				}
			}
			
			//Section Enumeration
			for(i = 0; i <= fileSize; i++){
				fseek(infile, i, SEEK_SET);
				fread(cmpBUFF, sizeof(cmpBUFF)+1, 1, infile);
				
				if(cmpBUFF[0] == 'P' && cmpBUFF[1] == 'E'){
					printf("PE Offset: 0x%x\n", i);
					i = i + 6;
					fseek(infile, i, SEEK_SET);
					fread(numSectionsBUFF, sizeof(numSectionsBUFF)+1, 1,infile);
					totalSections = numSectionsBUFF[0] | (numSectionsBUFF[1]<<8);
					printf("Number of Sections: %d\n", totalSections);
					i = i + 114;
					fseek(infile, i, SEEK_SET);
					fread(exptblBUFF, sizeof(exptblBUFF)+1, 1, infile);
					exptblINT = exptblBUFF[0] | (exptblBUFF[1]<<8) | (exptblBUFF[2]<<16) | (exptblBUFF[3]<<24);
					printf("Export Table RVA: 0x%02x%02x%02x%02x\n", exptblBUFF[3], exptblBUFF[2], exptblBUFF[1], exptblBUFF[0]);
				}
				
				//.text
				if (cmpBUFF[0] == '.' && cmpBUFF[1] == 't' && cmpBUFF[2] == 'e' && cmpBUFF[3] == 'x' && cmpBUFF[4] == 't'){
					numSections++;
					textOFFSET = i;
					printf(".text offset: 0x%x\n", i);
					i = i + 12;
					fseek(infile, i, SEEK_SET);
					fread(rvaBUFF, sizeof(rvaBUFF)+1, 1,infile);
					rvaINT = rvaBUFF[0] | (rvaBUFF[1]<<8) | (rvaBUFF[2]<<16) | (rvaBUFF[3]<<24);
					printf("RVA: 0x%02x%02x%02x%02x\n", rvaBUFF[3], rvaBUFF[2], rvaBUFF[1], rvaBUFF[0]);
					i = i + 8;
					fseek(infile, i, SEEK_SET);
					fread(rawdataBUFF, sizeof(rawdataBUFF)+1, 1,infile);
					rawdataINT = rawdataBUFF[0] | (rawdataBUFF[1]<<8) | (rawdataBUFF[2]<<16) | (rawdataBUFF[3]<<24);
					printf("Raw Data Ptr: 0x%02x%02x%02x%02x\n", rawdataBUFF[3], rawdataBUFF[2], rawdataBUFF[1], rawdataBUFF[0]);
					rvaOFFSET = rvaINT - rawdataINT;
					printf("RVA vs RAW: 0x%x\n", rvaOFFSET);
					rvavsrawINT = exptblINT - rvaOFFSET;
					i = rvavsrawINT + 12;
					fseek(infile, i, SEEK_SET);
					fread(namervatblBUFF, sizeof(namervatblBUFF)+1, 1,infile);
					namervaINT = namervatblBUFF[0] | (namervatblBUFF[1]<<8) | (namervatblBUFF[2]<<16) | (namervatblBUFF[3]<<24);
					namestblINT = namervaINT - rvaOFFSET;
					if(namestblINT < 0 || namestblINT > fileSize){
					}
					else{
						//Find .dll
						j = namestblINT;
						fseek(infile, j, SEEK_SET);
						fread(dllBUFF, sizeof(dllBUFF)+1, 1, infile); //Read buffer
						for(j = 0; j <= MAX_PATH; j++){
							if(dllBUFF[j] == '.' && dllBUFF[j+1] == 'd' && dllBUFF[j+2] == 'l' && dllBUFF[j+3] == 'l'){
								namestblOFFSET = j+namestblINT+4;
								namestblBOOL = true;
								i = rvavsrawINT + 12;
								i = i + 8+4;
								fseek(infile, i, SEEK_SET);
								fread(numfuncBuff, sizeof(numfuncBuff)+1, 1, infile);
								numFunctions = numfuncBuff[0] | (numfuncBuff[1]<<8) | (numfuncBuff[2]<<16) | (numfuncBuff[3]<<24);
								printf("Number of Functions: %d\n", numFunctions);
								break;
							}
						}
					}
					i = textOFFSET + 32;
					fseek(infile, i, SEEK_SET);
				}
				
				//.data
				if (cmpBUFF[0] == '.' && cmpBUFF[1] == 'd' && cmpBUFF[2] == 'a' && cmpBUFF[3] == 't' && cmpBUFF[4] == 'a'){
					numSections++;
					dataOFFSET = i;
					printf(".data offset: 0x%x\n", i);
					i = i + 12;
					fseek(infile, i, SEEK_SET);
					fread(rvaBUFF, sizeof(rvaBUFF)+1, 1,infile);
					rvaINT = rvaBUFF[0] | (rvaBUFF[1]<<8) | (rvaBUFF[2]<<16) | (rvaBUFF[3]<<24);
					printf("RVA: 0x%02x%02x%02x%02x\n", rvaBUFF[3], rvaBUFF[2], rvaBUFF[1], rvaBUFF[0]);
					i = i + 8;
					fseek(infile, i, SEEK_SET);
					fread(rawdataBUFF, sizeof(rawdataBUFF)+1, 1,infile);
					rawdataINT = rawdataBUFF[0] | (rawdataBUFF[1]<<8) | (rawdataBUFF[2]<<16) | (rawdataBUFF[3]<<24);
					printf("Raw Data Ptr: 0x%02x%02x%02x%02x\n", rawdataBUFF[3], rawdataBUFF[2], rawdataBUFF[1], rawdataBUFF[0]);
					rvaOFFSET = rvaINT - rawdataINT;
					printf("RVA vs RAW: 0x%x\n", rvaOFFSET);
					rvavsrawINT = exptblINT - rvaOFFSET;
					i = rvavsrawINT +  12;
					fseek(infile, i, SEEK_SET);
					fread(namervatblBUFF, sizeof(namervatblBUFF)+1, 1,infile);
					namervaINT = namervatblBUFF[0] | (namervatblBUFF[1]<<8) | (namervatblBUFF[2]<<16) | (namervatblBUFF[3]<<24);
					namestblINT = namervaINT - rvaOFFSET;
					if(namestblINT < 0 || namestblINT > fileSize){
					}
					else{
						//Find .dll
						j = namestblINT;
						fseek(infile, j, SEEK_SET);
						fread(dllBUFF, sizeof(dllBUFF)+1, 1, infile); //Read buffer
						for(j = 0; j <= MAX_PATH; j++){
							if(dllBUFF[j] == '.' && dllBUFF[j+1] == 'd' && dllBUFF[j+2] == 'l' && dllBUFF[j+3] == 'l'){
								namestblOFFSET = j+namestblINT+4;
								namestblBOOL = true;
								i = rvavsrawINT + 12;
								i = i + 8+4;
								fseek(infile, i, SEEK_SET);
								fread(numfuncBuff, sizeof(numfuncBuff)+1, 1, infile);
								numFunctions = numfuncBuff[0] | (numfuncBuff[1]<<8) | (numfuncBuff[2]<<16) | (numfuncBuff[3]<<24);
								printf("Number of Functions: %d\n", numFunctions);
								break;
							}
						}
					}
						i = dataOFFSET + 32;
						fseek(infile, i, SEEK_SET);
				}
				
				//.rdata
				if (cmpBUFF[0] == '.' && cmpBUFF[1] == 'r' && cmpBUFF[2] == 'd' && cmpBUFF[3] == 'a' && cmpBUFF[4] == 't' && cmpBUFF[5] == 'a'){
					numSections++;
					rdataOFFSET = i;
					printf(".rdata offset: 0x%x\n", i);
					i = i + 12;
					fseek(infile, i, SEEK_SET);
					fread(rvaBUFF, sizeof(rvaBUFF)+1, 1,infile);
					rvaINT = rvaBUFF[0] | (rvaBUFF[1]<<8) | (rvaBUFF[2]<<16) | (rvaBUFF[3]<<24);
					printf("RVA: 0x%02x%02x%02x%02x\n", rvaBUFF[3], rvaBUFF[2], rvaBUFF[1], rvaBUFF[0]);
					i = i + 8;
					fseek(infile, i, SEEK_SET);
					fread(rawdataBUFF, sizeof(rawdataBUFF)+1, 1,infile);
					rawdataINT = rawdataBUFF[0] | (rawdataBUFF[1]<<8) | (rawdataBUFF[2]<<16) | (rawdataBUFF[3]<<24);
					printf("Raw Data Ptr: 0x%02x%02x%02x%02x\n", rawdataBUFF[3], rawdataBUFF[2], rawdataBUFF[1], rawdataBUFF[0]);
					rvaOFFSET = rvaINT - rawdataINT;
					printf("RVA vs RAW: 0x%x\n", rvaOFFSET);
					rvavsrawINT = exptblINT - rvaOFFSET;
					i = rvavsrawINT +  12;
					fseek(infile, i, SEEK_SET);
					fread(namervatblBUFF, sizeof(namervatblBUFF)+1, 1,infile);
					namervaINT = namervatblBUFF[0] | (namervatblBUFF[1]<<8) | (namervatblBUFF[2]<<16) | (namervatblBUFF[3]<<24);
					namestblINT = namervaINT - rvaOFFSET;
					if(namestblINT < 0 || namestblINT > fileSize){
					}
					else{
						//Find .dll
						j = namestblINT;
						fseek(infile, j, SEEK_SET);
						fread(dllBUFF, sizeof(dllBUFF)+1, 1, infile); //Read buffer
						for(j = 0; j <= MAX_PATH; j++){
							if(dllBUFF[j] == '.' && dllBUFF[j+1] == 'd' && dllBUFF[j+2] == 'l' && dllBUFF[j+3] == 'l'){
								namestblOFFSET = j+namestblINT+4;
								namestblBOOL = true;
								i = rvavsrawINT + 12;
								i = i + 8+4;
								fseek(infile, i, SEEK_SET);
								fread(numfuncBuff, sizeof(numfuncBuff)+1, 1, infile);
								numFunctions = numfuncBuff[0] | (numfuncBuff[1]<<8) | (numfuncBuff[2]<<16) | (numfuncBuff[3]<<24);
								printf("Number of Functions: %d\n", numFunctions);
								break;
							}
						}
					}
					i = rdataOFFSET + 32;
					fseek(infile, i, SEEK_SET);
				}
				
				//.bss
				if (cmpBUFF[0] == '.' && cmpBUFF[1] == 'b' && cmpBUFF[2] == 's' && cmpBUFF[3] == 's'){
					numSections++;
					bssOFFSET = i;
					printf(".bss offset: 0x%x\n", i);
					i = i + 12;
					fseek(infile, i, SEEK_SET);
					fread(rvaBUFF, sizeof(rvaBUFF)+1, 1,infile);
					rvaINT = rvaBUFF[0] | (rvaBUFF[1]<<8) | (rvaBUFF[2]<<16) | (rvaBUFF[3]<<24);
					printf("RVA: 0x%02x%02x%02x%02x\n", rvaBUFF[3], rvaBUFF[2], rvaBUFF[1], rvaBUFF[0]);
					i = i + 8;
					fseek(infile, i, SEEK_SET);
					fread(rawdataBUFF, sizeof(rawdataBUFF)+1, 1,infile);
					rawdataINT = rawdataBUFF[0] | (rawdataBUFF[1]<<8) | (rawdataBUFF[2]<<16) | (rawdataBUFF[3]<<24);
					printf("Raw Data Ptr: 0x%02x%02x%02x%02x\n", rawdataBUFF[3], rawdataBUFF[2], rawdataBUFF[1], rawdataBUFF[0]);
					rvaOFFSET = rvaINT - rawdataINT;
					printf("RVA vs RAW: 0x%x\n", rvaOFFSET);
					rvavsrawINT = exptblINT - rvaOFFSET;
					i = rvavsrawINT +  12;
					fseek(infile, i, SEEK_SET);
					fread(namervatblBUFF, sizeof(namervatblBUFF)+1, 1,infile);
					namervaINT = namervatblBUFF[0] | (namervatblBUFF[1]<<8) | (namervatblBUFF[2]<<16) | (namervatblBUFF[3]<<24);
					namestblINT = namervaINT - rvaOFFSET;
					if(namestblINT < 0 || namestblINT > fileSize){
					}
					else{
						//Find .dll
						j = namestblINT;
						fseek(infile, j, SEEK_SET);
						fread(dllBUFF, sizeof(dllBUFF)+1, 1, infile); //Read buffer
						for(j = 0; j <= MAX_PATH; j++){
							if(dllBUFF[j] == '.' && dllBUFF[j+1] == 'd' && dllBUFF[j+2] == 'l' && dllBUFF[j+3] == 'l'){
								namestblOFFSET = j+namestblINT+4;
								namestblBOOL = true;
								i = rvavsrawINT + 12;
								i = i + 8+4;
								fseek(infile, i, SEEK_SET);
								fread(numfuncBuff, sizeof(numfuncBuff)+1, 1, infile);
								numFunctions = numfuncBuff[0] | (numfuncBuff[1]<<8) | (numfuncBuff[2]<<16) | (numfuncBuff[3]<<24);
								printf("Number of Functions: %d\n", numFunctions);
								break;
							}
						}
					}
						i = bssOFFSET + 32;
						fseek(infile, i, SEEK_SET);
				}
				
				//.edata
				if (cmpBUFF[0] == '.' && cmpBUFF[1] == 'e' && cmpBUFF[2] == 'd' && cmpBUFF[3] == 'a' && cmpBUFF[4] == 't' && cmpBUFF[5] == 'a'){
					numSections++;
					edataOFFSET = i;
					printf(".edata offset: 0x%x\n", i);
					i = i + 12;
					fseek(infile, i, SEEK_SET);
					fread(rvaBUFF, sizeof(rvaBUFF)+1, 1,infile);
					rvaINT = rvaBUFF[0] | (rvaBUFF[1]<<8) | (rvaBUFF[2]<<16) | (rvaBUFF[3]<<24);
					printf("RVA: 0x%02x%02x%02x%02x\n", rvaBUFF[3], rvaBUFF[2], rvaBUFF[1], rvaBUFF[0]);
					i = i + 8;
					fseek(infile, i, SEEK_SET);
					fread(rawdataBUFF, sizeof(rawdataBUFF)+1, 1,infile);
					rawdataINT = rawdataBUFF[0] | (rawdataBUFF[1]<<8) | (rawdataBUFF[2]<<16) | (rawdataBUFF[3]<<24);
					printf("Raw Data Ptr: 0x%02x%02x%02x%02x\n", rawdataBUFF[3], rawdataBUFF[2], rawdataBUFF[1], rawdataBUFF[0]);
					rvaOFFSET = rvaINT - rawdataINT;
					printf("RVA vs RAW: 0x%x\n", rvaOFFSET);
					rvavsrawINT = exptblINT - rvaOFFSET;
					i = rvavsrawINT +  12;
					fseek(infile, i, SEEK_SET);
					fread(namervatblBUFF, sizeof(namervatblBUFF)+1, 1,infile);
					namervaINT = namervatblBUFF[0] | (namervatblBUFF[1]<<8) | (namervatblBUFF[2]<<16) | (namervatblBUFF[3]<<24);
					namestblINT = namervaINT - rvaOFFSET;
					if(namestblINT < 0 || namestblINT > fileSize){
					}
					else{
						//Find .dll
						j = namestblINT;
						fseek(infile, j, SEEK_SET);
						fread(dllBUFF, sizeof(dllBUFF)+1, 1, infile); //Read buffer
						for(j = 0; j <= MAX_PATH; j++){
							if(dllBUFF[j] == '.' && dllBUFF[j+1] == 'd' && dllBUFF[j+2] == 'l' && dllBUFF[j+3] == 'l'){
								namestblOFFSET = j+namestblINT+4;
								namestblBOOL = true;
								i = rvavsrawINT + 12;
								i = i + 8+4;
								fseek(infile, i, SEEK_SET);
								fread(numfuncBuff, sizeof(numfuncBuff)+1, 1, infile);
								numFunctions = numfuncBuff[0] | (numfuncBuff[1]<<8) | (numfuncBuff[2]<<16) | (numfuncBuff[3]<<24);
								printf("Number of Functions: %d\n", numFunctions);
								break;
							}
						}
					}
					i = edataOFFSET + 32;
					fseek(infile, i, SEEK_SET);
				}
			
				//.idata
				if (cmpBUFF[0] == '.' && cmpBUFF[1] == 'i' && cmpBUFF[2] == 'd' && cmpBUFF[3] == 'a' && cmpBUFF[4] == 't' && cmpBUFF[5] == 'a'){
					numSections++;
					idataOFFSET = i;
					printf(".idata offset: 0x%x\n", i);
					i = i + 12;
					fseek(infile, i, SEEK_SET);
					fread(rvaBUFF, sizeof(rvaBUFF)+1, 1,infile);
					rvaINT = rvaBUFF[0] | (rvaBUFF[1]<<8) | (rvaBUFF[2]<<16) | (rvaBUFF[3]<<24);
					printf("RVA: 0x%02x%02x%02x%02x\n", rvaBUFF[3], rvaBUFF[2], rvaBUFF[1], rvaBUFF[0]);
					i = i + 8;
					fseek(infile, i, SEEK_SET);
					fread(rawdataBUFF, sizeof(rawdataBUFF)+1, 1,infile);
					rawdataINT = rawdataBUFF[0] | (rawdataBUFF[1]<<8) | (rawdataBUFF[2]<<16) | (rawdataBUFF[3]<<24);
					printf("Raw Data Ptr: 0x%02x%02x%02x%02x\n", rawdataBUFF[3], rawdataBUFF[2], rawdataBUFF[1], rawdataBUFF[0]);
					rvaOFFSET = rvaINT - rawdataINT;
					printf("RVA vs RAW: 0x%x\n", rvaOFFSET);
					rvavsrawINT = exptblINT - rvaOFFSET;
					i = rvavsrawINT +  12;
					fseek(infile, i, SEEK_SET);
					fread(namervatblBUFF, sizeof(namervatblBUFF)+1, 1,infile);
					namervaINT = namervatblBUFF[0] | (namervatblBUFF[1]<<8) | (namervatblBUFF[2]<<16) | (namervatblBUFF[3]<<24);
					namestblINT = namervaINT - rvaOFFSET;
					if(namestblINT < 0 || namestblINT > fileSize){
					}
					else{
						//Find .dll
						j = namestblINT;
						fseek(infile, j, SEEK_SET);
						fread(dllBUFF, sizeof(dllBUFF)+1, 1, infile); //Read buffer
						for(j = 0; j <= MAX_PATH; j++){
							if(dllBUFF[j] == '.' && dllBUFF[j+1] == 'd' && dllBUFF[j+2] == 'l' && dllBUFF[j+3] == 'l'){
								namestblOFFSET = j+namestblINT+4;
								namestblBOOL = true;
								i = rvavsrawINT + 12;
								i = i + 8+4;
								fseek(infile, i, SEEK_SET);
								fread(numfuncBuff, sizeof(numfuncBuff)+1, 1, infile);
								numFunctions = numfuncBuff[0] | (numfuncBuff[1]<<8) | (numfuncBuff[2]<<16) | (numfuncBuff[3]<<24);
								printf("Number of Functions: %d\n", numFunctions);
								break;
							}
						}
					}
					i = idataOFFSET + 32;
					fseek(infile, i, SEEK_SET);
				}
				
				//.CRT
				if (cmpBUFF[0] == '.' && cmpBUFF[1] == 'C' && cmpBUFF[2] == 'R' && cmpBUFF[3] == 'T'){
					numSections++;
					crtOFFSET = i; 
					printf(".CRT offset: 0x%x\n", i);
					i = i + 12;
					fseek(infile, i, SEEK_SET);
					fread(rvaBUFF, sizeof(rvaBUFF)+1, 1,infile);
					rvaINT = rvaBUFF[0] | (rvaBUFF[1]<<8) | (rvaBUFF[2]<<16) | (rvaBUFF[3]<<24);
					printf("RVA: 0x%02x%02x%02x%02x\n", rvaBUFF[3], rvaBUFF[2], rvaBUFF[1], rvaBUFF[0]);
					i = i + 8;
					fseek(infile, i, SEEK_SET);
					fread(rawdataBUFF, sizeof(rawdataBUFF)+1, 1,infile);
					rawdataINT = rawdataBUFF[0] | (rawdataBUFF[1]<<8) | (rawdataBUFF[2]<<16) | (rawdataBUFF[3]<<24);
					printf("Raw Data Ptr: 0x%02x%02x%02x%02x\n", rawdataBUFF[3], rawdataBUFF[2], rawdataBUFF[1], rawdataBUFF[0]);
					rvaOFFSET = rvaINT - rawdataINT;
					printf("RVA vs RAW: 0x%x\n", rvaOFFSET);
					rvavsrawINT = exptblINT - rvaOFFSET;
					i = rvavsrawINT +  12;
					fseek(infile, i, SEEK_SET);
					fread(namervatblBUFF, sizeof(namervatblBUFF)+1, 1,infile);
					namervaINT = namervatblBUFF[0] | (namervatblBUFF[1]<<8) | (namervatblBUFF[2]<<16) | (namervatblBUFF[3]<<24);
					namestblINT = namervaINT - rvaOFFSET;
					if(namestblINT < 0 || namestblINT > fileSize){
					}
					else{
						//Find .dll
						j = namestblINT;
						fseek(infile, j, SEEK_SET);
						fread(dllBUFF, sizeof(dllBUFF)+1, 1, infile); //Read buffer
						for(j = 0; j <= MAX_PATH; j++){
							if(dllBUFF[j] == '.' && dllBUFF[j+1] == 'd' && dllBUFF[j+2] == 'l' && dllBUFF[j+3] == 'l'){
								namestblOFFSET = j+namestblINT+4;
								namestblBOOL = true;
								i = rvavsrawINT + 12;
								i = i + 8+4;
								fseek(infile, i, SEEK_SET);
								fread(numfuncBuff, sizeof(numfuncBuff)+1, 1, infile);
								numFunctions = numfuncBuff[0] | (numfuncBuff[1]<<8) | (numfuncBuff[2]<<16) | (numfuncBuff[3]<<24);
								printf("Number of Functions: %d\n", numFunctions);
								break;
							}
						}
					}
					i = crtOFFSET + 32;
					fseek(infile, i, SEEK_SET);
				}
				
				//.tls
				if (cmpBUFF[0] == '.' && cmpBUFF[1] == 't' && cmpBUFF[2] == 'l' && cmpBUFF[3] == 's'){
					numSections++;
					tlsOFFSET = i;
					printf(".tls offset: 0x%x\n", i);
					i = i + 12;
					fseek(infile, i, SEEK_SET);
					fread(rvaBUFF, sizeof(rvaBUFF)+1, 1,infile);
					rvaINT = rvaBUFF[0] | (rvaBUFF[1]<<8) | (rvaBUFF[2]<<16) | (rvaBUFF[3]<<24);
					printf("RVA: 0x%02x%02x%02x%02x\n", rvaBUFF[3], rvaBUFF[2], rvaBUFF[1], rvaBUFF[0]);
					i = i + 8;
					fseek(infile, i, SEEK_SET);
					fread(rawdataBUFF, sizeof(rawdataBUFF)+1, 1,infile);
					rawdataINT = rawdataBUFF[0] | (rawdataBUFF[1]<<8) | (rawdataBUFF[2]<<16) | (rawdataBUFF[3]<<24);
					printf("Raw Data Ptr: 0x%02x%02x%02x%02x\n", rawdataBUFF[3], rawdataBUFF[2], rawdataBUFF[1], rawdataBUFF[0]);
					rvaOFFSET = rvaINT - rawdataINT;
					printf("RVA vs RAW: 0x%x\n", rvaOFFSET);
					rvavsrawINT = exptblINT - rvaOFFSET;
					i = rvavsrawINT +  12;
					fseek(infile, i, SEEK_SET);
					fread(namervatblBUFF, sizeof(namervatblBUFF)+1, 1,infile);
					namervaINT = namervatblBUFF[0] | (namervatblBUFF[1]<<8) | (namervatblBUFF[2]<<16) | (namervatblBUFF[3]<<24);
					namestblINT = namervaINT - rvaOFFSET;
					if(namestblINT < 0 || namestblINT > fileSize){
					}
					else{
						//Find .dll
						j = namestblINT;
						fseek(infile, j, SEEK_SET);
						fread(dllBUFF, sizeof(dllBUFF)+1, 1, infile); //Read buffer
						for(j = 0; j <= MAX_PATH; j++){
							if(dllBUFF[j] == '.' && dllBUFF[j+1] == 'd' && dllBUFF[j+2] == 'l' && dllBUFF[j+3] == 'l'){
								namestblOFFSET = j+namestblINT+4;
								namestblBOOL = true;
								i = rvavsrawINT + 12;
								i = i + 8+4;
								fseek(infile, i, SEEK_SET);
								fread(numfuncBuff, sizeof(numfuncBuff)+1, 1, infile);
								numFunctions = numfuncBuff[0] | (numfuncBuff[1]<<8) | (numfuncBuff[2]<<16) | (numfuncBuff[3]<<24);
								printf("Number of Functions: %d\n", numFunctions);
								break;
							}
						}
					}
					i = tlsOFFSET + 32;
					fseek(infile, i, SEEK_SET);
				}

				//.rsrc
				if (cmpBUFF[0] == '.' && cmpBUFF[1] == 'r' && cmpBUFF[2] == 's' && cmpBUFF[3] == 'r' && cmpBUFF[4] == 'c'){
					numSections++;
					rsrcOFFSET = i;
					printf(".rsrc offset: 0x%x\n", i);
					i = i + 12;
					fseek(infile, i, SEEK_SET);
					fread(rvaBUFF, sizeof(rvaBUFF)+1, 1,infile);
					rvaINT = rvaBUFF[0] | (rvaBUFF[1]<<8) | (rvaBUFF[2]<<16) | (rvaBUFF[3]<<24);
					printf("RVA: 0x%02x%02x%02x%02x\n", rvaBUFF[3], rvaBUFF[2], rvaBUFF[1], rvaBUFF[0]);
					i = i + 8;
					fseek(infile, i, SEEK_SET);
					fread(rawdataBUFF, sizeof(rawdataBUFF)+1, 1,infile);
					rawdataINT = rawdataBUFF[0] | (rawdataBUFF[1]<<8) | (rawdataBUFF[2]<<16) | (rawdataBUFF[3]<<24);
					printf("Raw Data Ptr: 0x%02x%02x%02x%02x\n", rawdataBUFF[3], rawdataBUFF[2], rawdataBUFF[1], rawdataBUFF[0]);
					rvaOFFSET = rvaINT - rawdataINT;
					printf("RVA vs RAW: 0x%x\n", rvaOFFSET);
					rvavsrawINT = exptblINT - rvaOFFSET;
					i = rvavsrawINT +  12;
					fseek(infile, i, SEEK_SET);
					fread(namervatblBUFF, sizeof(namervatblBUFF)+1, 1,infile);
					namervaINT = namervatblBUFF[0] | (namervatblBUFF[1]<<8) | (namervatblBUFF[2]<<16) | (namervatblBUFF[3]<<24);
					namestblINT = namervaINT - rvaOFFSET;
					if(namestblINT < 0 || namestblINT > fileSize){
					}
					else{
						//Find .dll
						j = namestblINT;
						fseek(infile, j, SEEK_SET);
						fread(dllBUFF, sizeof(dllBUFF)+1, 1, infile); //Read buffer
						for(j = 0; j <= MAX_PATH; j++){
							if(dllBUFF[j] == '.' && dllBUFF[j+1] == 'd' && dllBUFF[j+2] == 'l' && dllBUFF[j+3] == 'l'){
								namestblOFFSET = j+namestblINT+4;
								namestblBOOL = true;
								i = rvavsrawINT + 12;
								i = i + 8+4;
								fseek(infile, i, SEEK_SET);
								fread(numfuncBuff, sizeof(numfuncBuff)+1, 1, infile);
								numFunctions = numfuncBuff[0] | (numfuncBuff[1]<<8) | (numfuncBuff[2]<<16) | (numfuncBuff[3]<<24);
								printf("Number of Functions: %d\n", numFunctions);
								break;
							}
						}
					}
					i = rsrcOFFSET + 32;
					fseek(infile, i, SEEK_SET);
				}
			
				//.reloc
				if (cmpBUFF[0] == '.' && cmpBUFF[1] == 'r' && cmpBUFF[2] == 'e' && cmpBUFF[3] == 'l' && cmpBUFF[4] == 'o' && cmpBUFF[5] == 'c'){
					numSections++;
					relocOFFSET = i;
					printf(".reloc offset: 0x%x\n", i);
					i = i + 12;
					fseek(infile, i, SEEK_SET);
					fread(rvaBUFF, sizeof(rvaBUFF)+1, 1,infile);
					rvaINT = rvaBUFF[0] | (rvaBUFF[1]<<8) | (rvaBUFF[2]<<16) | (rvaBUFF[3]<<24);
					printf("RVA: 0x%02x%02x%02x%02x\n", rvaBUFF[3], rvaBUFF[2], rvaBUFF[1], rvaBUFF[0]);
					i = i + 8;
					fseek(infile, i, SEEK_SET);
					fread(rawdataBUFF, sizeof(rawdataBUFF)+1, 1,infile);
					rawdataINT = rawdataBUFF[0] | (rawdataBUFF[1]<<8) | (rawdataBUFF[2]<<16) | (rawdataBUFF[3]<<24);
					printf("Raw Data Ptr: 0x%02x%02x%02x%02x\n", rawdataBUFF[3], rawdataBUFF[2], rawdataBUFF[1], rawdataBUFF[0]);
					rvaOFFSET = rvaINT - rawdataINT;
					printf("RVA vs RAW: 0x%x\n", rvaOFFSET);
					rvavsrawINT = exptblINT - rvaOFFSET;
					i = rvavsrawINT +  12;
					fseek(infile, i, SEEK_SET);
					fread(namervatblBUFF, sizeof(namervatblBUFF)+1, 1,infile);
					namervaINT = namervatblBUFF[0] | (namervatblBUFF[1]<<8) | (namervatblBUFF[2]<<16) | (namervatblBUFF[3]<<24);
					namestblINT = namervaINT - rvaOFFSET;
					if(namestblINT < 0 || namestblINT > fileSize){
					}
					else{
						//Find .dll
						j = namestblINT;
						fseek(infile, j, SEEK_SET);
						fread(dllBUFF, sizeof(dllBUFF)+1, 1, infile); //Read buffer
						for(j = 0; j <= MAX_PATH; j++){
							if(dllBUFF[j] == '.' && dllBUFF[j+1] == 'd' && dllBUFF[j+2] == 'l' && dllBUFF[j+3] == 'l'){
								namestblOFFSET = j+namestblINT+4;
								namestblBOOL = true;
								i = rvavsrawINT + 12;
								i = i + 8+4;
								fseek(infile, i, SEEK_SET);
								fread(numfuncBuff, sizeof(numfuncBuff)+1, 1, infile);
								numFunctions = numfuncBuff[0] | (numfuncBuff[1]<<8) | (numfuncBuff[2]<<16) | (numfuncBuff[3]<<24);
								printf("Number of Functions: %d\n", numFunctions);
								break;
							}
						}
					}
					i = relocOFFSET + 32;
					fseek(infile, i, SEEK_SET);
				}
		
				if(numSections == totalSections){
					break;
				}
			}
			if(namestblBOOL == true){
				printf("NAME TABLE OFFSET FOUND: 0x%x", namestblOFFSET);
				if (boolList == true && boolEnum == true){
					printf("\n");
				}
			}
			if(namestblBOOL == false){
				printf("CANNOT FIND NAME TABLE OFFSET.");
				if (boolList == true && boolEnum == true){
					printf("\n");
				}
			}
		
			fseek(infile, namestblINT, SEEK_SET);
			fread(namesdllBuff, sizeof(namesdllBuff)+1, 1, infile);
			//printf("Names Header: %s\n", namesdllBuff);
			for(i = 0; i <= MAX_PATH; i++){
				if(namesdllBuff[i] == '.' && namesdllBuff[i+1] == 'd' && namesdllBuff[i+2] == 'l' && namesdllBuff[i+3] == 'l'){
					namesOffset = i + namestblINT + 4;
					//printf("Names Offset: 0x%x", namesOffset);
					break;
				}
			}	
		}
	}
	
	if(boolList == true && boolEnum == true){
		//printf("\n");
		for(i = namestblOFFSET+1; i <= fileSize; i++){
			if(i == namestblOFFSET+1){
				printf("---ENUMERATED FUNCTIONS---\n");
				printf("VA:        Function Name:\n");
				//printf("Act Addr:  Function Name:\n");
			}
			fseek(infile, i, SEEK_SET);
			fread(singleByte, sizeof(singleByte)+1, 1, infile);
			functionName[functNameInt] = singleByte[0];
			functNameInt++;
			if (singleByte[0] == '\x00'){
				printAddress(argv[argEnum+1], functionName);
				printf(" %s\n", functionName);
				functNameInt = 0;
				functCount++;
				if (functCount == numFunctions){
					printf("---END ENUMERATED FUNCTIONS---");
					break;
				}
			}
		}
	}
	
	if(boolEnum == true){
		fclose(infile);
	}
	return 0;
}