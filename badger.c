//--------------------------//
//---------BADGER-----------//
//-BY: ARC NETWORK SECURITY-//
//--------------------------//

#include <windows.h>
#include <stdio.h>
#include <string.h>

//Get File Size
int getFileSize(FILE *inputFile){
	int fileSize;
	fseek(inputFile, 0L, SEEK_END);
	fileSize = ftell(inputFile);
	return fileSize;
}

//Help Display
void help(){
	printf("Made by: Arc Network Security\n");
	printf("Examples:\nbadger --aslr-check\nbadger --lib library.dll function\nbadger --enable-dep or --disable-dep\nbadger --enum library.dll\nbadger --about\n");
	printf("Descriptions:\n");
	printf("--aslr-check: Shows RSP and ESP to aid in discovering ASLR best run several times, if values change ASLR is enabled.\n");
	printf("--lib: Shows the function actual address when loaded into memory ASLR may change this if enabled\n");
	printf("--enable-dep and --disable--dep: Requires administrator command prompt and will allow to enable/disable DEP for troubleshooting.\n");
	printf("--enum: This will give library headers and information including functions and actual addresses\n");
	printf("--about: The about screen");
}

//About Display
void about(){
	printf("---ABOUT---\n");
	printf("Version: 1.0a\n");
	printf("Made By: Arc Network Security\n");
	printf("Website: www.arcnetworksecurity.com\n");
	printf("This application is designed to be the Swiss Army Knife of windows exploit development\n");
	printf("Allowing exploit developers to think more about development than the repetitive tasks done everyday\n");
	printf("To participate in this project email lilly@arcnetworksecurity.com\n");
	printf("---FEATURES TO COME---\n");
	printf("- SEH Detection and Enumeration\n");
	printf("- Mangled RVA Table Fix (some PE files don't have correct RVA Table Offset Flag i.e. user32.dll)\n");
	printf("- Alpha-Numberic Shellcode Reference\n");
	printf("- Suggestions are welcome");
}

int main(int argc, char *argv[]) {
	if (argc < 2){
		printf("Not Enough Arguments.\n");
		help();
		return 1;
	}
	
	//This is how help screens should be done in practice!
	if ((strcmp(argv[1], "--help") == 0) || (strcmp(argv[1], "-h") == 0)) {
		printf("---BADGER HELP---\n");
		help();
		return 0;
	}
	
	if(strcmp(argv[1], "--about") == 0){
		about();
		return 0;
	}
	
	//Enable DEP Requires Administrator Rights
	//Can also get DEP policy by doing GetSystemDEPPolicy(void);3
	//IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE if set to 0x0040 ASLR is enabled for dll
	//IMAGE_DLLCHARACTERISTICS_NX_COMPAT = 0x0100 and DEP is enabled for dll
	if (strcmp(argv[1], "--enable-dep") == 0){
		system("bcdedit.exe /set {current} nx AlwaysOn");
		return 0;
	}
	
	//Disable DEP Requires Administrator Rights
	if (strcmp(argv[1], "--disable-dep") == 0){
		system("bcdedit.exe /set {current} nx AlwaysOff");
		return 0;
	}
	
	//A simple check for ASLR
	if (strcmp(argv[1], "--aslr-check") == 0){
		register int esp asm("esp");
		register int rsp asm("rsp");
		printf("Run Multiple Time if Changes ASLR is Enabled.\n");
		printf("x86 ESP: 0x%x\n", esp);
		printf("x64 RSP: 0x%x", rsp);
		return 0;
	}
	
	//Get Actual Address of DLL Function
	if(strcmp(argv[1], "--lib") == 0){
		unsigned int api_addr = 0;
		if(argc < 3){
			printf("Please include library file.");
			return 1;
		}
		if (GetProcAddress(LoadLibraryA(argv[2]), argv[3]) == 0){
			printf("Please specify correct function name.");
			return 1;
		}
		printf("Address: 0x%x", GetProcAddress(LoadLibraryA(argv[2]), argv[3]));
		return 0;
	}
	
	//Enumerate functions and display library header info
	if (strcmp(argv[1], "--enum") == 0){
	FILE *infile;
	int fileSize;
	unsigned char sbuff[1];
	unsigned char cmpbuff[2];
	unsigned char exptblBuffLE[3];
	unsigned char exptblBuff[3];
	unsigned char actbaseBuff[3];
	unsigned char namervaBuff[3];
	unsigned char numfuncBuff[3];
	long int numFuncInt;
	long int i;
	long int j;
	long int k;
	long int l;
	cmpbuff[0] = 'P';
	cmpbuff[1] = 'E';
	
	infile = fopen(argv[2], "rb"); //Open file for reading
	if (!infile){
		printf("Unable to read or find file provided.");
		return 1;
	}
	//Store file name and print
	char fileName[MAX_PATH];
	strcpy(fileName,argv[2]);
	printf("File Name: %s\n", fileName);
	//Print File Size
	fileSize = getFileSize(infile);
	printf("File Size: %d bytes\n", getFileSize(infile));
	
	//Begin Searching for PE Flag
	for (i = 0; i <= fileSize; i++){
		fseek(infile, i, SEEK_SET);
		fread(sbuff, sizeof(sbuff)+1,1, infile);
		if (cmpbuff[0] == sbuff[0] && cmpbuff[1] == sbuff[1]){
			printf("PE Header Flag: 0x%x\n", i);
			printf("PE Header Offset: 0x%x\n", i+2); //+2 for length of PE flag
			i = i + 52;
			fseek(infile, i, SEEK_SET);
			fread(actbaseBuff, sizeof(actbaseBuff)+1,1,infile);
			printf("Preferred Base: 0x%02x%02x%02x%02x\n", actbaseBuff[3], actbaseBuff[2], actbaseBuff[1], actbaseBuff[0]);
			i = i + 42; 
			fseek(infile, i, SEEK_SET);
			fread(sbuff, sizeof(sbuff)+1,1, infile);
			printf("DLL Characteristics: 0x%02x%02x\n", sbuff[1], sbuff[0]);
			if (sbuff[1] == '\x01'){
				printf("DEP is Enabled\n");
			}
			else {
				printf("DEP is Disabled\n");
			}
			if (sbuff[0] == '\x40'){
				printf("ASLR is Enabled\n");
			}
			else {
				printf("ASLR is Disabled\n");
			}
			//Find Export table or IMAGE_EXPORT_DIRECTORY
			i = i + 24+2;
			fseek(infile, i, SEEK_SET);
			fread(exptblBuffLE, sizeof(exptblBuffLE)+1, 1, infile);
			printf("Export Table Offset: 0x%02x%02x%02x%02x\n", exptblBuffLE[3], exptblBuffLE[2], exptblBuffLE[1], exptblBuffLE[0]);
			//Convert exptblBuffLE to non little endian format move to for loop eventually
			exptblBuff[0] = exptblBuffLE[3];
			exptblBuff[1] = exptblBuffLE[2]; 
			exptblBuff[2] = exptblBuffLE[1];
			exptblBuff[3] = exptblBuffLE[0];
			i = 0;
			i += exptblBuffLE[0] | (exptblBuffLE[1]<<8) | (exptblBuffLE[2]<<16) | (exptblBuffLE[3]<<24);
			//printf("Offset to Table: %d\n", i);
			i = i + 12;
			fseek(infile, i, SEEK_SET);
			fread(namervaBuff, sizeof(namervaBuff)+1, 1, infile);
			printf("Name RVA Offset: 0x%02x%02x%02x%02x\n", namervaBuff[3], namervaBuff[2], namervaBuff[1], namervaBuff[0]);
			//Here we will find Number of Functions +8 should do it!
			i = i + 8;
			fseek(infile, i, SEEK_SET);
			fread(numfuncBuff, sizeof(numfuncBuff)+1, 1, infile);
			numFuncInt = 0;
			numFuncInt += numfuncBuff[0] | (numfuncBuff[1]<<8) | (numfuncBuff[2]<<16) | (numfuncBuff[3]<<24); //Convert edian to int
			printf("Number of functions: %d\n", numFuncInt);
			//End number of Functions
			i = 0;
			i += namervaBuff[0] | (namervaBuff[1]<<8) | (namervaBuff[2]<<16) | (namervaBuff[3]<<24);
			//Some PE files don't have pointer header to name rva table like user32.dll... will have to brute force based on filename
			fseek(infile, i, SEEK_SET);
			unsigned char filenameBuff[MAX_PATH];
			unsigned char dotdllBuff[3];
			dotdllBuff[0] = '.';
			dotdllBuff[1] = 'd';
			dotdllBuff[2] = 'l';
			dotdllBuff[3] = 'l';
			int foundDll = 0;
			fread(filenameBuff, sizeof(filenameBuff)+1, 1, infile);
			//printf("filenameBuff: %s\n", filenameBuff);
			for (j = 0; j <= MAX_PATH; j++){
				//Get .dll
				if (dotdllBuff[1] == filenameBuff[j] && dotdllBuff[2] == filenameBuff[j+1] && dotdllBuff[3] == filenameBuff[j+2]){
					printf("Function Name Offset: 0x%x\n", j+4+i);
					foundDll = 1;
					//Start enumerating functions
					
					long int difference = i+j+4;
					unsigned char nullByte = '\x00';
					unsigned char singleByte[1];
					unsigned char functionName[MAX_PATH];
					long int functNameInt = 0;
					long int functCount = 0;
					printf("---ENUMERATED FUNCTIONS---\n");
					printf("Act Addr:  Function Name:\n");
					//Offset 756820
					for (k = difference; k <= fileSize; k++){
						fseek(infile, k, SEEK_SET);
						fread(singleByte, sizeof(singleByte)+1, 1, infile);
						
						//printf("%02x%02x\n", singleByte[0], singleByte[1]);
						functionName[functNameInt] = singleByte[0];
						functNameInt++;
						
						if (singleByte[0] == '\x00'){
							//unsigned int api_addr = 0;
							//api_addr = GetProcAddress(LoadLibraryA(argv[1]),functionName);
							//printf("Address: 0x%x", api_addr);
							printf("0x%x %s\n", GetProcAddress(LoadLibraryA(argv[2]),functionName), functionName);
							functNameInt = 0;
							functCount++;
							if (functCount == numFuncInt){
								//system("pause");
								printf("---END ENUMERATED FUNCTIONS---");
								break;
							}
						}
					}
					
					//End enumerating functions
					break;
				}
				if (j == MAX_PATH && foundDll == 0){
					printf("Brute force feature not available yet\n");
					printf("Name RVA Offset Missing... start enumerating functions with brute force...");
				}
			}
			break;
		}
	}
	fclose(infile);
	}
	else {
		printf("Unknown Error\n");
		help(); 
		return 1;
	}
		
}
