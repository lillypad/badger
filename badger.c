//---------------------------//
//----------BADGER-----------//
//---BY: Lilly Chalupowski---//
//---------------------------//

//Includes
#include <stdio.h>
#include <windows.h>
#include <libgen.h>
#include <time.h>
#include "documentation.h"

//Defines
#define WINDOWS
#ifdef WINDOWS
#define MAX_PATH 260
#endif
#ifdef LINUX
#define MAX_PATH 255
#endif
#define UINT_MAX 2147483647

//DOS Struct
struct  DOSStruct {
	char mz[2];
	char lastsize[2];
	char PagesInFile[2];
	char relocations[2];
	char HeaderSizeInParagraph[2];
	char MinExtraParagraphNeeded[2];
	char MaxExtraParagraphNeeded[2];
	char InitialSS[2];
	char InitialSP[2];
	char checksum[2];
	char InitialIP[2];
	char InitialCS[2];
	char FileAddOfRelocTable[2];
	char OverlayNumber[2];
	char res_0[8];
	char OEMIdentifier[2];
	char OEMInformation[2];
	char res_1[20];
	int PEOffset;
};

struct dotStruct {
        unsigned char dotName[5];
	unsigned char res_0[3];
	unsigned char VirtualSize[4];
	unsigned char RVA[4];
	unsigned char SizeOfRawData[4];
	unsigned char PointerToRawData[4];
	unsigned char PointerToRelocations[4];
	unsigned char PointerToLineNumbers[4];
	unsigned char NumberOfRelocations[2];
	unsigned char NumberOfLineNumbers[2];
	unsigned char Characteristics[4];
        //PAD For Struct Bug
        unsigned char pad[5];
};

struct PEStruct {
	unsigned char pe[4];
	unsigned char TargetMachine[2];
	short NumberOfSections;
	unsigned int TimeDateStamp;
	unsigned char PointerToSymbolTable[4];
	unsigned char NumberOfSymbols[4];
	unsigned char SizeOfOptionalHeaders[2];
	unsigned char Characteristics[2];
	unsigned char exe[2];
	unsigned char lnMajVer[1];
	unsigned char lnMnrVer[1];
	unsigned char SizeOfCode[4];
	unsigned char SizeOfInitializedData[4];
	unsigned char SizeOfUnInitializedData[4];
	unsigned char AddressOfEntryPoint[4];
	unsigned char BaseOfCode[4];
	unsigned char BaseOfData[4];
	unsigned char ImageBase[4];
	unsigned char SectionAlignment[4];
	unsigned char FileAlignment[4];
	unsigned char MajorOSVersion[2];
	unsigned char MinorOSVersion[2];
	unsigned char MajorImageVersion[2];
	unsigned char MinorImageVersion[2];
	unsigned char MajorSubSystemVersion[2];
	unsigned char MinorSubSystemVersion[2];
	unsigned char Win32VersionValue[4];
	unsigned char SizeOfImage[4];
	unsigned char SizeOfHeaders[4];
	unsigned char CheckSum_0[4];
	unsigned char CheckSum_1[2];
	unsigned char DllCharacteristics[2];
	unsigned char SizeOfStackReserve[4];
	unsigned char SizeOfStackCommit[4];
	unsigned char SizeOfHeapReserve[4];
	unsigned char SizeOfHeapCommit[4];
	unsigned char LoaderFlags[4];
	unsigned char NumberOfRVAandSizes[4];
	unsigned char ExportTableRVA[4];
	unsigned char ExportTableSize[4];
	unsigned char ImportTableRVA[4];
	unsigned char ImportTableSize[4];
	unsigned char ResourceTableRVA[4];
	unsigned char ResourceTableSize[4];
	unsigned char ExceptionTableRVA[4];
	unsigned char ExceptionTableSize[4];
	unsigned char CertificateTableOffset[4];
	unsigned char CertificateTableSize[4];
	unsigned char BaseRelocationTableRVA[4];
	unsigned char BaseRelocationTableSize[4];
	unsigned char DebugDirectoryRVA[4];
	unsigned char DebugDirectorySize[4];
	unsigned char ArcSpecificDataRVA[4];
	unsigned char ArcSpecificDataSize[4];
	unsigned char GlobalPointerRegisterRVA[4];
	unsigned char GlobalPointerRegisterSize[4];
	unsigned char TLSTableRVA[4];
	unsigned char TLSTableSize[4];
	unsigned char LoadConfigurationTableRVA[4];
	unsigned char LoadConfigurationTableSize[4];
	unsigned char BoundImportTableRVA[4];
	unsigned char BoundImportTableSize[4];
	unsigned char ImportAddressTableRVA[4];
	unsigned char ImportAddressTableSize[4];
	unsigned char DelayImportDescriptorsRVA[4];
	unsigned char DelayImportDescriptorsSize[4];
	unsigned char CLIHeaderRVA_0[4];
	unsigned char CLIHeaderSize_0[4];
	unsigned char CLIHeaderRVA_1[4];
	unsigned char CLIHeaderSize_1[4];
};

//IMAGE_EXPORT_DIRECTORY STRUCT
struct STRUCT_IMAGE_EXPORT_DIRECTORY {
	unsigned char Characteristics[4];
	unsigned char TimeDateStamp[4];
	unsigned char MajorVersion[2];
	unsigned char MinorVersion[2];
	unsigned char NameRVA[4];
	unsigned char OrdinalBase[4];
	unsigned char NumberOfFunctions[4];
	unsigned char NumberOfNames[4];
	unsigned char AddressOfFunctions[4];
	unsigned char AddressOfNames[4];
	unsigned char AddressOfNameOrdinals[4];
};

struct STRUCT_IMAGE_LOAD_CONFIG_DIRECTORY {
	unsigned char Size[4];
	unsigned char TimeDateStamp[4];
	unsigned char MajorVersion[2];
	unsigned char MinorVersion[2];
	unsigned char GlobalFlagsClear[4];
	unsigned char GlobalFlagsSet[4];
	unsigned char CriticalSectionDefaultTimeout[4];
	unsigned char DeCommitFreeBlockThreshold[4];
	unsigned char DeCommitTotalFreeThreshold[4];
	unsigned char LockPrefixTableVA[4];
	unsigned char MaximumAllocationSize[4];
	unsigned char VirtualMemoryThreshold[4];
	unsigned char ProcessHeapFlags[4];
	unsigned char ProcessAffinityMask[4];
	unsigned char CSDVersion[2];
	unsigned char Reserved[2];
	unsigned char EditListVA[4];
	unsigned char SecurityCookieVA[4];
	unsigned char SEHandlerTableVA[4];
	unsigned char SEHandlerCount[4];
	//unsigned char pad[4];
};

//Boolean Type
typedef int bool;
#define true 1
#define false 0

//Print Function Address
void printAddress(char fileName[MAX_PATH], char functionName[MAX_PATH]){
        printf("0x%x", GetProcAddress(LoadLibraryA(fileName), functionName));
}

//Print Stack Pointer
void printSP(){
	register int esp asm("esp");
	register int rsp asm("rsp");
	printf("Run Multiple Times\n");
	printf("x86 ESP: 0x%x\n", esp);
	printf("x64 RSP: 0x%x\n", rsp);
}

//Arg Check
bool argCheck(char *argv[], char strArg[MAX_PATH], int argc){
	int i;
	for (i = 0; i <= argc-1; i++){
		if (strcmp(argv[i], strArg) == 0){
			return true;
		}
	}
	return false;
}

int argNum(char *argv[], char strArg[MAX_PATH], int argc){
        int i;
        for (i = 0; i <= argc-1; i++){
                if (strcmp(argv[i], strArg) == 0){
                        return i;
                }
        }
        return -1;
}

//Get File Size
int getFileSize(FILE *inputFile){
	int fileSize;
	fseek(inputFile, 0L, SEEK_END);
	fileSize = ftell(inputFile);
	return fileSize;
}

//Word To Int
int wordToInt(unsigned char buff[]){
	long int value = buff[0] | (buff[1]<<8) | (buff[2]<<16) | (buff[3]<<24);
	return value;
}

//Print Hex
void printHex(char text[], char buff[], int buffSize){
	int i;
	printf("%s", text);
	printf("0x");
	for (i = 0; i <= buffSize-1; i++){
		if(buff[i] == '\x00'){
			printf("00");
		}
		else{
			printf("%02x", (unsigned char)buff[i]);
		}
	}
	printf("\n");
}

//Print Hex LE
void printHexLE(char text[], char buff[], int buffSize){
	int i;
	printf("%s", text);
	printf("0x");
	for (i = buffSize-1; i >= 0; i--){
		if(buff[i] == '\x00'){
			printf("00");
		}
		else{
			printf("%02x", (unsigned char)buff[i]);
		}
	}
	printf("\n");
}

bool printFuncAddress(char fileName[MAX_PATH], char functionName[MAX_PATH]){
	int address = (int)GetProcAddress(LoadLibraryA(fileName), functionName);
	if (address == 0){
		fprintf(stderr, "ERROR: Please Specify Correct Function Name\n");
		return 1;
	}
        printf("---BEGIN SINGLE FUNCTION---\n");
        printf("%s RVA = ", functionName);
        printf("0x%x\n", address);
	printf("---END SINGLE FUNCTION---\n");
}

//Main Program
int main(int argc, char *argv[]){
	//Input File Pointer
	FILE * inputFile;

	//Initalize DOS & PE Header
	struct DOSStruct DOSHeader;
	struct PEStruct PEHeader;
	struct dotStruct dotHeader;
	struct STRUCT_IMAGE_EXPORT_DIRECTORY IMAGE_EXPORT_DIRECTORY;
	struct STRUCT_IMAGE_LOAD_CONFIG_DIRECTORY IMAGE_LOAD_CONFIG_DIRECTORY;

	//Check For Args
	if (argc < 2){
		printf("ERROR: Not enough arguments.\n");
		help();
		return 1;
	}

	//Help
	if ( argCheck(argv, "--help", argc) || argCheck(argv, "-h", argc) ){
		help();
		return 0;
	}

	if ( argCheck(argv, "--version", argc) || argCheck(argv, "-v", argc) ){
		printf("v3.0\n");
		return 0;
	}

	//About
	if (argCheck(argv, "--about", argc)){
		about();
		return 0;
	}

	//Alphanumeric Shellcode Reference
	if (argCheck(argv, "--alpha-ref", argc)){
		alphaNumericRef();
		return 0;
	}

	//ASLR Checker
	if (argCheck(argv, "--aslr-check", argc)){
		printSP();
		return 0;
	}

	//Enable DEP
	if (argCheck(argv, "--enable-dep", argc)){
		int stderror = system("bcdedit.exe /set {current} nx AlwaysOn");
		if (stderror == 1){
			printf("Please Run --enable-dep as Admin.\n");
			return 1;
		}
	}

	//Disable DEP
	if (argCheck(argv, "--disable-dep", argc)){
		int stderror = system("bcedit.exe /set {current} nx AlwaysOff");
		if (stderror == 1){
			printf("Please run --disable-dep as Admin.\n");
			return 1;
		}
	}

	//Enumerate Function ASLR Entropy
	if (argCheck(argv, "--bruter", argc)){
		static unsigned char nibble1;
		static unsigned char nibble2;
		static int n[8] = {0, 0, 0, 0, 0, 0, 0, 0};
		static int i, j, k, l, m;
		static int addr;
		static unsigned char c[4];
		static int iterations;
		iterations = atoi(argv[argNum(argv, "--bruter", argc) + 3]);
		if (iterations > UINT_MAX){
			fprintf(stderr, "Max iterations supported %d\n", UINT_MAX);
			return 1;
		}
		printf("Iterations: %d\n", iterations);
		printf("Initial Value: 0x%x\n",(int)GetProcAddress(LoadLibraryA(argv[argNum(argv, "--bruter", argc)+1]), argv[argNum(argv, "--bruter", argc)+2]));
		for (m = 0; m < iterations; m++){
			for (i = 0; i <= 3; i++){
				addr = (int)GetProcAddress(LoadLibraryA(argv[argNum(argv, "--bruter", argc)+1]), argv[argNum(argv, "--bruter", argc)+2]);
				c[0] = (addr >> 24) & 0xFF;
				c[1] = (addr >> 16) & 0xFF;
				c[2] = (addr >> 8) & 0xFF;
				c[3] = addr & 0xFF;

				nibble1 = (c[i] & 0xF0);
				nibble2 = (c[i] & 0x0F);

				addr = (int)GetProcAddress(LoadLibraryA(argv[argNum(argv, "--bruter", argc)+1]), argv[argNum(argv, "--bruter", argc)+2]);
				c[0] = (addr >> 24) & 0xFF;
				c[1] = (addr >> 16) & 0xFF;
				c[2] = (addr >> 8) & 0xFF;
				c[3] = addr & 0xFF;

				if (nibble1 != (c[i] & 0xF0)){
					n[i*2] = 1;
				}
				if (nibble2 != (c[i] & 0x0F)){
					n[i*2+1] = 1;
				}
			}
		}
		for (k = 0; k < 8; k++){
			if(k ==0){l=0;}
			printf("l: %d\n", n[k]);
			if (n[k] == 1){
				l++;
			}
		}
		printf("Entropy: %dbit\n", l*4);
		return 0;
	}

	//Check One Function RVA
	if (argCheck(argv, "--lib", argc)){
		if (argc < 4){
			fprintf(stderr, "ERROR: Need More Arguments\n");
			return 1;
		}
		printFuncAddress(argv[argNum(argv, "--lib", argc)+1], argv[argNum(argv, "--lib", argc)+2]);
		return 0;
	}

	//Display the IMAGE_LOAD_CONFIG_DIRECTORY
	if (argCheck(argv, "--ilcd-header", argc)){
		inputFile = fopen(argv[argNum(argv, "--ilcd-header", argc)+1], "r");
		if (!inputFile){ fprintf(stderr, "ERROR: Unable to read file specified.\n"); return 1; }
		fread(&DOSHeader, 1, sizeof(DOSHeader)-1, inputFile);
		fseek(inputFile, DOSHeader.PEOffset, SEEK_SET);
		fread(&PEHeader, 1, sizeof(PEHeader)-1, inputFile);
		static int arrayRVAvsRAW[50];
		static int arraySectionOffsets[50];
		static int arraySizeOfRawData[50];
		static int arrayPointerToRawData[50];
		int i;
		for(i = 0; i <= PEHeader.NumberOfSections-1; i++){
			arraySectionOffsets[i] = DOSHeader.PEOffset + sizeof(PEHeader) + ((sizeof(dotHeader)-sizeof(dotHeader.pad))*i);
			fseek(inputFile, DOSHeader.PEOffset + sizeof(PEHeader) + ((sizeof(dotHeader)-sizeof(dotHeader.pad))*i), SEEK_SET);
			fread(&dotHeader, 1, sizeof(dotHeader)-1, inputFile);
			arrayRVAvsRAW[i] = (wordToInt(dotHeader.RVA) - wordToInt(dotHeader.PointerToRawData));
			arraySizeOfRawData[i] = wordToInt(dotHeader.SizeOfRawData);
			arrayPointerToRawData[i] = wordToInt(dotHeader.PointerToRawData);
			if (( (wordToInt(PEHeader.LoadConfigurationTableRVA)-arrayRVAvsRAW[i]) < (arraySizeOfRawData[i]+arrayPointerToRawData[i]) )
			&& ( (wordToInt(PEHeader.LoadConfigurationTableRVA)-arrayRVAvsRAW[i]) >= arrayPointerToRawData[i] )) {
				fseek(inputFile, (wordToInt(PEHeader.LoadConfigurationTableRVA) - arrayRVAvsRAW[i]), SEEK_SET);
				fread(&IMAGE_LOAD_CONFIG_DIRECTORY, 1, sizeof(IMAGE_LOAD_CONFIG_DIRECTORY)-1, inputFile);
				printf("---BEGIN IMAGE LOAD CONFIG DIRECTORY HEADER---\n");
				printf("Size                          = 0x%x\n", wordToInt(IMAGE_LOAD_CONFIG_DIRECTORY.Size));
				printf("TimeDateStamp                 = 0x%x\n", wordToInt(IMAGE_LOAD_CONFIG_DIRECTORY.TimeDateStamp));
				printf("MajorVersion                  = 0x%x\n", wordToInt(IMAGE_LOAD_CONFIG_DIRECTORY.MajorVersion));
				printf("MinorVersion                  = 0x%x\n", wordToInt(IMAGE_LOAD_CONFIG_DIRECTORY.MinorVersion));
				printf("GlobalFlagsClear              = 0x%x\n", wordToInt(IMAGE_LOAD_CONFIG_DIRECTORY.GlobalFlagsClear));
				printf("GlobalFlagsSet                = 0x%x\n", wordToInt(IMAGE_LOAD_CONFIG_DIRECTORY.GlobalFlagsSet));
				printf("CriticalSectionDefaultTimeout = 0x%x\n", wordToInt(IMAGE_LOAD_CONFIG_DIRECTORY.CriticalSectionDefaultTimeout));
				printf("DeCommitFreeBlockThreshold    = 0x%x\n", wordToInt(IMAGE_LOAD_CONFIG_DIRECTORY.DeCommitFreeBlockThreshold));
				printf("DeCommitTotalFreeThreshold    = 0x%x\n", wordToInt(IMAGE_LOAD_CONFIG_DIRECTORY.DeCommitTotalFreeThreshold));
				printf("LockPrefixTableVA             = 0x%x\n", wordToInt(IMAGE_LOAD_CONFIG_DIRECTORY.LockPrefixTableVA));
				printf("MaximumAllocationSize         = 0x%x\n", wordToInt(IMAGE_LOAD_CONFIG_DIRECTORY.MaximumAllocationSize));
				printf("VirtualMemoryThreshold        = 0x%x\n", wordToInt(IMAGE_LOAD_CONFIG_DIRECTORY.VirtualMemoryThreshold));
				printf("ProcessHeapFlags              = 0x%x\n", wordToInt(IMAGE_LOAD_CONFIG_DIRECTORY.ProcessHeapFlags));
				printf("ProcessAffinityMask           = 0x%x\n", wordToInt(IMAGE_LOAD_CONFIG_DIRECTORY.ProcessAffinityMask));
				printf("CSDVersion                    = 0x%x\n", wordToInt(IMAGE_LOAD_CONFIG_DIRECTORY.CSDVersion));
				printf("Reserved                      = 0x%x\n", wordToInt(IMAGE_LOAD_CONFIG_DIRECTORY.Reserved));
				printf("EditListVA                    = 0x%x\n", wordToInt(IMAGE_LOAD_CONFIG_DIRECTORY.EditListVA));
				printf("SecurityCookieVA              = 0x%x\n", wordToInt(IMAGE_LOAD_CONFIG_DIRECTORY.SecurityCookieVA));
				printf("SEHandlerTableVA              = 0x%x\n", wordToInt(IMAGE_LOAD_CONFIG_DIRECTORY.SEHandlerTableVA));
				printf("SEHandlerCount                = 0x%x\n", wordToInt(IMAGE_LOAD_CONFIG_DIRECTORY.SEHandlerCount));
				printf("---END IMAGE LOAD CONFIG DIRECTORY HEADER---\n");
			}
		}
	return 0;
	}

	//Enumerate Protections
	if (argCheck(argv, "--check-security", argc)){
		inputFile = fopen(argv[argNum(argv, "--check-security", argc)+1], "r");
                if (!inputFile){ fprintf(stderr, "ERROR: Unable to read file specified.\n"); return 1; }
                fread(&DOSHeader, 1, sizeof(DOSHeader)-1, inputFile);
                fseek(inputFile, DOSHeader.PEOffset, SEEK_SET);
                fread(&PEHeader, 1, sizeof(PEHeader)-1, inputFile);
		printf("---BEGIN SECURITY---\n");
		//Microsoft Sets these in Nibbles must use bitwise masking
		if ((PEHeader.DllCharacteristics[0] & 0xF0) == '\x40'){
			printf("ASLR                     = Enabled\n");
		}
		else{
			printf("ASLR                     = Disabled\n");
		}
		if ((PEHeader.DllCharacteristics[1] & 0x0F)== '\x01'){
			printf("DEP                      = Enabled\n");
		}
		else{
			printf("DEP                      = Disabled\n");
		}
		if ((PEHeader.DllCharacteristics[1] & 0x0F)== '\x04'){
			printf("SEH                      = Disabled\n");
		}
		else{
			printf("SEH                      = Enabled\n");
		}
		//Get SEH and Security Cookies
		static int arrayRVAvsRAW[50];
		static int arraySectionOffsets[50];
		static int arraySizeOfRawData[50];
		static int arrayPointerToRawData[50];
		int i;
		for(i = 0; i <= PEHeader.NumberOfSections-1; i++){
			arraySectionOffsets[i] = DOSHeader.PEOffset + sizeof(PEHeader) + ((sizeof(dotHeader)-sizeof(dotHeader.pad))*i);
			fseek(inputFile, DOSHeader.PEOffset + sizeof(PEHeader) + ((sizeof(dotHeader)-sizeof(dotHeader.pad))*i), SEEK_SET);
			fread(&dotHeader, 1, sizeof(dotHeader)-1, inputFile);
			arrayRVAvsRAW[i] = (wordToInt(dotHeader.RVA) - wordToInt(dotHeader.PointerToRawData));
			arraySizeOfRawData[i] = wordToInt(dotHeader.SizeOfRawData);
			arrayPointerToRawData[i] = wordToInt(dotHeader.PointerToRawData);
			if (( (wordToInt(PEHeader.LoadConfigurationTableRVA)-arrayRVAvsRAW[i]) < (arraySizeOfRawData[i]+arrayPointerToRawData[i]) )
			&& ( (wordToInt(PEHeader.LoadConfigurationTableRVA)-arrayRVAvsRAW[i]) >= arrayPointerToRawData[i] )) {
				fseek(inputFile, (wordToInt(PEHeader.LoadConfigurationTableRVA) - arrayRVAvsRAW[i]), SEEK_SET);
				fread(&IMAGE_LOAD_CONFIG_DIRECTORY, 1, sizeof(IMAGE_LOAD_CONFIG_DIRECTORY)-1, inputFile);
				printf("LOAD_CONFIGURATION_TABLE = 0x%x\n", (wordToInt(PEHeader.LoadConfigurationTableRVA) - arrayRVAvsRAW[i]) );
				printHexLE("Security Cookie VA       = ",IMAGE_LOAD_CONFIG_DIRECTORY.SecurityCookieVA, sizeof(IMAGE_LOAD_CONFIG_DIRECTORY.SecurityCookieVA));
				printHexLE("SEH Table VA             = ", IMAGE_LOAD_CONFIG_DIRECTORY.SEHandlerTableVA, sizeof(IMAGE_LOAD_CONFIG_DIRECTORY.SEHandlerTableVA));
				printHexLE("SEH Count                = ", IMAGE_LOAD_CONFIG_DIRECTORY.SEHandlerCount, sizeof(IMAGE_LOAD_CONFIG_DIRECTORY.SEHandlerCount));
			}
		}
		printf("---END SECURITY---\n");
		fclose(inputFile);
		return 0;
	}

	//Display DOS Header
	if (argCheck(argv, "--dos-header", argc)){
		inputFile = fopen(argv[argNum(argv, "--dos-header", argc)+1], "r");
		if (!inputFile){ fprintf(stderr, "ERROR: Unable to read file specified.\n"); return 1; }
		fread(&DOSHeader, 1, sizeof(DOSHeader)-1, inputFile);
		printf("---BEGIN DOS HEADER---\n");
		printf("Offset                  = 0x0\n");
		printf("File Size               = %d\n", getFileSize(inputFile));
		printHex("MZ                      = ", DOSHeader.mz, sizeof(DOSHeader.mz));
		printHexLE("lastsize                = ", DOSHeader.lastsize, sizeof(DOSHeader.lastsize));
		printHexLE("PagesInFile             = ", DOSHeader.PagesInFile, sizeof(DOSHeader.PagesInFile));
		printHex("relocations             = ", DOSHeader.relocations, sizeof(DOSHeader.relocations));
		printHexLE("HeaderSizeInParagraph   = ", DOSHeader.HeaderSizeInParagraph, sizeof(DOSHeader.HeaderSizeInParagraph));
		printHexLE("MinExtraParagraphNeeded = ", DOSHeader.MinExtraParagraphNeeded, sizeof(DOSHeader.MinExtraParagraphNeeded));
		printHexLE("MaxExtraParagraphNeeded = ", DOSHeader.MaxExtraParagraphNeeded, sizeof(DOSHeader.MaxExtraParagraphNeeded));
		printHexLE("InitialSS               = ", DOSHeader.InitialSS, sizeof(DOSHeader.InitialSS));
		printHexLE("InitialSP               = ", DOSHeader.InitialSP, sizeof(DOSHeader.InitialSP));
		printHex("checksum                = ", DOSHeader.checksum, sizeof(DOSHeader.checksum));
		printHex("InitialIP               = ", DOSHeader.InitialIP, sizeof(DOSHeader.InitialIP));
		printHex("InitialCS               = ", DOSHeader.InitialCS, sizeof(DOSHeader.InitialCS));
		printHexLE("FileAddOfRelocTable     = ", DOSHeader.FileAddOfRelocTable, sizeof(DOSHeader.FileAddOfRelocTable));
		printHexLE("OverlayNumber           = ", DOSHeader.OverlayNumber, sizeof(DOSHeader.OverlayNumber));
		printHex("res_0                   = ", DOSHeader.res_0, sizeof(DOSHeader.res_0));
		printHex("OEMIdentifier           = ", DOSHeader.OEMIdentifier, sizeof(DOSHeader.OEMIdentifier));
		printHex("OEMInformation          = ", DOSHeader.OEMInformation, sizeof(DOSHeader.OEMInformation));
		printHex("res_1                   = ", DOSHeader.res_1, sizeof(DOSHeader.res_1));
		printf("PEOffset                = 0x%x\n", DOSHeader.PEOffset);
		printf("---END DOS HEADER---\n");
		fclose(inputFile);
		return 0;

	}

	//Enumerate Functions Table / Virtual Addresses
	if (argCheck(argv, "--enum-func", argc)){
		static int arrayRVAvsRAW[50];
		static int arraySectionOffsets[50];
		static int arraySizeOfRawData[50];
		static int arrayPointerToRawData[50];
		static int j;
		static unsigned char singleByte[1];
		static int nullCount = 0;
		static int prevNullPointer = 0;
		static int nextNullPointer = 0;
		static char functionName[MAX_PATH];
		static int funcCount = 0;
		static int funcNameInt = 0;
		bool first = true;
		inputFile = fopen(argv[argNum(argv, "--enum-func", argc)+1], "r");
                if (!inputFile){ fprintf(stderr, "ERROR: Unable to read file specified.\n"); return 1; }
                fread(&DOSHeader, 1, sizeof(DOSHeader)-1, inputFile);
                fseek(inputFile, DOSHeader.PEOffset, SEEK_SET);
                fread(&PEHeader, 1, sizeof(PEHeader)-1, inputFile);
		int i;
		for (i = 0; i <= PEHeader.NumberOfSections-1; i++){
			arraySectionOffsets[i] = DOSHeader.PEOffset + sizeof(PEHeader) + ((sizeof(dotHeader)-sizeof(dotHeader.pad))*i);
                        fseek(inputFile, DOSHeader.PEOffset + sizeof(PEHeader) + ((sizeof(dotHeader)-sizeof(dotHeader.pad))*i), SEEK_SET);
			fread(&dotHeader, 1, sizeof(dotHeader)-1, inputFile);
			arrayRVAvsRAW[i] = (wordToInt(dotHeader.RVA) - wordToInt(dotHeader.PointerToRawData));
			arraySizeOfRawData[i] = wordToInt(dotHeader.SizeOfRawData);
			arrayPointerToRawData[i] = wordToInt(dotHeader.PointerToRawData);
			if (( (wordToInt(PEHeader.ExportTableRVA)-arrayRVAvsRAW[i]) < (arraySizeOfRawData[i]+arrayPointerToRawData[i]) )
			&& ( (wordToInt(PEHeader.ExportTableRVA)-arrayRVAvsRAW[i]) >= arrayPointerToRawData[i] )) {
				fseek(inputFile, (wordToInt(PEHeader.ExportTableRVA) - arrayRVAvsRAW[i]), SEEK_SET);
				fread(&IMAGE_EXPORT_DIRECTORY, 1, sizeof(IMAGE_EXPORT_DIRECTORY)-1, inputFile);
				printf("---BEGIN FUNCTION ENUMERATION---\n");
				printf("Number Of Functions: %d\n", wordToInt(IMAGE_EXPORT_DIRECTORY.NumberOfNames));
				printf("Export Names Offset: 0x%x\n", (wordToInt(IMAGE_EXPORT_DIRECTORY.NameRVA) - arrayRVAvsRAW[i]));
				printf("Virtual Address:          Function Names:\n");
				for (j = (wordToInt(IMAGE_EXPORT_DIRECTORY.NameRVA) - arrayRVAvsRAW[i]); j <= getFileSize(inputFile); j++){
					fseek(inputFile, j, SEEK_SET);
					fread(singleByte, sizeof(singleByte)+1, 1, inputFile);
					functionName[funcNameInt] = singleByte[0];
					funcNameInt++;
					if (singleByte[0] == '\x00'){
						if (first == false){
							printAddress(argv[argNum(argv, "--enum-func", argc)+1], functionName);
							printf("                %s\n", functionName);
						}
						first = false;
						funcNameInt = 0;
						funcCount++;
						if (funcCount == wordToInt(IMAGE_EXPORT_DIRECTORY.NumberOfNames)+1 ){
							printf("--END FUNCTION ENUMERATION--\n");
							break;;
						}
					}
				}
			}
		}
		fclose(inputFile);
		return 0;
	}

	//Display PE Header
	if (argCheck(argv, "--pe-header", argc)){
		inputFile = fopen(argv[argNum(argv, "--pe-header", argc)+1], "r");
		if (!inputFile){ fprintf(stderr, "ERROR: Unable to read file specified.\n"); return 1; }
		fread(&DOSHeader, 1, sizeof(DOSHeader)-1, inputFile);
		fseek(inputFile, DOSHeader.PEOffset, SEEK_SET);
		fread(&PEHeader, 1, sizeof(PEHeader)-1, inputFile);
		printf("---BEGIN PE HEADER---\n");
		printf("Offset                      = 0x%x\n", DOSHeader.PEOffset);
		printf("File Size                   = %d\n", getFileSize(inputFile));
		printHex("PE                          = ", PEHeader.pe, sizeof(PEHeader.pe));
		printHexLE("TargetMachine               = ", PEHeader.TargetMachine, sizeof(PEHeader.TargetMachine));
		printf("NumberOfSections            = 0x%x\n", PEHeader.NumberOfSections);
		time_t tm = PEHeader.TimeDateStamp;
		if (PEHeader.TimeDateStamp != 0){
			printf("TimeDateStamp               = %s",ctime( &tm ));
		}
		if (PEHeader.TimeDateStamp == 0){
			printf("TimeDateStamp               = N/A\n");
		}
		printHexLE("PointerToSymbolTable        = ", PEHeader.PointerToSymbolTable, sizeof(PEHeader.PointerToSymbolTable));
		printHexLE("NumberOfSymbols             = ", PEHeader.NumberOfSymbols, sizeof(PEHeader.NumberOfSymbols));
		printHexLE("SizeOfOptionalHeaders       = ", PEHeader.SizeOfOptionalHeaders, sizeof(PEHeader.SizeOfOptionalHeaders));
		printHexLE("Characteristics             = ", PEHeader.Characteristics, sizeof(PEHeader.Characteristics));
		printHexLE("Magic                       = ", PEHeader.exe, sizeof(PEHeader.exe));
		printHexLE("lnMajVer                    = ", PEHeader.lnMajVer, sizeof(PEHeader.lnMajVer));
		printHexLE("lnMnrVer                    = ", PEHeader.lnMnrVer, sizeof(PEHeader.lnMnrVer));
		printHexLE("SizeOfCode                  = ", PEHeader.SizeOfCode, sizeof(PEHeader.SizeOfCode));
		printHexLE("SizeOfInitializedData       = ", PEHeader.SizeOfInitializedData, sizeof(PEHeader.SizeOfInitializedData));
		printHexLE("SizeOfUnInitializedData     = ", PEHeader.SizeOfUnInitializedData, sizeof(PEHeader.SizeOfUnInitializedData));
		printHexLE("AddressOfEntryPoint         = ", PEHeader.AddressOfEntryPoint, sizeof(PEHeader.AddressOfEntryPoint));
		printHexLE("BaseOfCode                  = ", PEHeader.BaseOfCode, sizeof(PEHeader.BaseOfCode));
		printHexLE("BaseOfData                  = ", PEHeader.BaseOfData, sizeof(PEHeader.BaseOfData));
		printHexLE("ImageBase                   = ", PEHeader.ImageBase, sizeof(PEHeader.ImageBase));
		printHex("SectionAlignment            = ", PEHeader.SectionAlignment, sizeof(PEHeader.SectionAlignment));
		printHex("FileAlignment               = ", PEHeader.FileAlignment, sizeof(PEHeader.FileAlignment));
		printHexLE("MajorOSVersion              = ", PEHeader.MajorOSVersion, sizeof(PEHeader.MajorOSVersion));
		printHexLE("MinorOSVersion              = ", PEHeader.MinorOSVersion, sizeof(PEHeader.MinorOSVersion));
		printHexLE("MajorImageVersion           = ", PEHeader.MajorImageVersion, sizeof(PEHeader.MajorImageVersion));
		printHexLE("MinorImageVersion           = ", PEHeader.MinorImageVersion, sizeof(PEHeader.MinorImageVersion));
		printHexLE("MajorSubSystemVersion       = ", PEHeader.MajorSubSystemVersion, sizeof(PEHeader.MajorSubSystemVersion));
		printHexLE("MinorSubSystemVersion       = ", PEHeader.MinorSubSystemVersion, sizeof(PEHeader.MinorSubSystemVersion));
		printHexLE("Win32VersionValue           = ", PEHeader.Win32VersionValue, sizeof(PEHeader.Win32VersionValue));
		printHexLE("SizeOfImage                 = ", PEHeader.SizeOfImage, sizeof(PEHeader.SizeOfImage));
		printHexLE("SizeOfHeaders               = ", PEHeader.SizeOfHeaders, sizeof(PEHeader.SizeOfHeaders));
		printHex("CheckSum_0                  = ", PEHeader.CheckSum_0, sizeof(PEHeader.CheckSum_0));
		printHex("CheckSum_1                  = ", PEHeader.CheckSum_1, sizeof(PEHeader.CheckSum_1));
		printHex("DllCharacteristics          = ", PEHeader.DllCharacteristics, sizeof(PEHeader.DllCharacteristics));
		printHexLE("SizeOfStackReserve          = ", PEHeader.SizeOfStackReserve, sizeof(PEHeader.SizeOfStackReserve));
		printHexLE("SizeOfStackCommit           = ", PEHeader.SizeOfStackCommit, sizeof(PEHeader.SizeOfStackCommit));
		printHexLE("SizeOfHeapReserve           = ", PEHeader.SizeOfHeapReserve, sizeof(PEHeader.SizeOfHeapReserve));
		printHexLE("SizeOfHeapCommit            = ", PEHeader.SizeOfHeapCommit, sizeof(PEHeader.SizeOfHeapCommit));
		printHex("LoaderFlags                 = ", PEHeader.LoaderFlags, sizeof(PEHeader.LoaderFlags));
		printHexLE("NumberOfRVAandSizes         = ", PEHeader.NumberOfRVAandSizes, sizeof(PEHeader.NumberOfRVAandSizes));
		printHexLE("ExportTableRVA              = ", PEHeader.ExportTableRVA, sizeof(PEHeader.ExportTableRVA));
		printHexLE("ExportTableSize             = ", PEHeader.ExportTableSize, sizeof(PEHeader.ExportTableSize));
		printHexLE("ImportTableRVA              = ", PEHeader.ImportTableRVA, sizeof(PEHeader.ImportTableRVA));
		printHexLE("ImportTableSize             = ", PEHeader.ImportTableSize, sizeof(PEHeader.ImportTableSize));
		printHexLE("ResourceTableRVA            = ", PEHeader.ResourceTableRVA, sizeof(PEHeader.ResourceTableRVA));
		printHexLE("ResourceTableSize           = ", PEHeader.ResourceTableSize, sizeof(PEHeader.ResourceTableSize));
		printHexLE("ExceptionTableRVA           = ", PEHeader.ExceptionTableRVA, sizeof(PEHeader.ExceptionTableRVA));
		printHexLE("ExceptionTableSize          = ", PEHeader.ExceptionTableSize, sizeof(PEHeader.ExceptionTableSize));
		printHexLE("CertificateTableOffset      = ", PEHeader.CertificateTableOffset, sizeof(PEHeader.CertificateTableOffset));
		printHexLE("CertificateTableSize        = ", PEHeader.CertificateTableSize, sizeof(PEHeader.CertificateTableSize));
		printHexLE("BaseRelocationTableRVA      = ", PEHeader.BaseRelocationTableRVA, sizeof(PEHeader.BaseRelocationTableRVA));
		printHexLE("BaseRelocationTableSize     = ", PEHeader.BaseRelocationTableSize, sizeof(PEHeader.BaseRelocationTableSize));
		printHexLE("DebugDirectoryRVA           = ", PEHeader.DebugDirectoryRVA, sizeof(PEHeader.DebugDirectoryRVA));
		printHexLE("DebugDirectorySize          = ", PEHeader.DebugDirectorySize, sizeof(PEHeader.DebugDirectorySize));
		printHexLE("ArcSpecificDataRVA          = ", PEHeader.ArcSpecificDataRVA, sizeof(PEHeader.ArcSpecificDataRVA));
		printHexLE("ArcSpecificDataSize         = ", PEHeader.ArcSpecificDataSize, sizeof(PEHeader.ArcSpecificDataSize));
		printHexLE("GlobalPointerRegisterRVA    = ", PEHeader.GlobalPointerRegisterRVA, sizeof(PEHeader.GlobalPointerRegisterRVA));
		printHexLE("GlobalPointerRegisterSize   = ", PEHeader.GlobalPointerRegisterSize, sizeof(PEHeader.GlobalPointerRegisterSize));
		printHexLE("TLSTableRVA                 = ", PEHeader.TLSTableRVA, sizeof(PEHeader.TLSTableRVA));
		printHexLE("TLSTableSize                = ", PEHeader.TLSTableSize, sizeof(PEHeader.TLSTableSize));
		printHexLE("LoadConfigurationTableRVA   = ", PEHeader.LoadConfigurationTableRVA, sizeof(PEHeader.LoadConfigurationTableRVA));
		printHexLE("LoadConfigurationTableSize  = ", PEHeader.LoadConfigurationTableSize, sizeof(PEHeader.LoadConfigurationTableSize));
		printHexLE("BoundImportTableRVA         = ", PEHeader.BoundImportTableRVA, sizeof(PEHeader.BoundImportTableRVA));
		printHexLE("BoundImportTableSize        = ", PEHeader.BoundImportTableSize, sizeof(PEHeader.BoundImportTableSize));
		printHexLE("ImportAddressTableRVA       = ", PEHeader.ImportAddressTableRVA, sizeof(PEHeader.ImportAddressTableRVA));
		printHexLE("ImportAddressTableSize      = ", PEHeader.ImportAddressTableSize, sizeof(PEHeader.ImportAddressTableSize));
		printHexLE("DelayImportDescriptorsRVA   = ", PEHeader.DelayImportDescriptorsRVA, sizeof(PEHeader.DelayImportDescriptorsRVA));
		printHexLE("DelayImportDescriptorsSize  = ", PEHeader.DelayImportDescriptorsSize, sizeof(PEHeader.DelayImportDescriptorsSize));
		printHexLE("CLIHeaderRVA_0              = ", PEHeader.CLIHeaderRVA_0, sizeof(PEHeader.CLIHeaderRVA_0));
		printHexLE("CLIHeaderSize_0             = ", PEHeader.CLIHeaderSize_0, sizeof(PEHeader.CLIHeaderSize_0));
		printHexLE("CLIHeaderRVA_1              = ", PEHeader.CLIHeaderRVA_1, sizeof(PEHeader.CLIHeaderRVA_1));
		printHexLE("CLIHeaderSize_1             = ", PEHeader.CLIHeaderSize_1, sizeof(PEHeader.CLIHeaderSize_1));
		int i;
		for (i = 0; i <= PEHeader.NumberOfSections-1; i++){
			fseek(inputFile, DOSHeader.PEOffset + sizeof(PEHeader) + ((sizeof(dotHeader)-sizeof(dotHeader.pad))*i), SEEK_SET);
			fread(&dotHeader, 1, sizeof(dotHeader)-1, inputFile);
			printf("%s                       = ", dotHeader.dotName);
			printHex("", dotHeader.dotName, sizeof(dotHeader.dotName));
			printf("%s Reserved              = ", dotHeader.dotName);
			printHex("", dotHeader.res_0, sizeof(dotHeader.res_0));
			printf("%s VirtualSize           = ", dotHeader.dotName);
			printHexLE("", dotHeader.VirtualSize, sizeof(dotHeader.VirtualSize));
			printf("%s RVA                   = ", dotHeader.dotName);
			printHexLE("", dotHeader.RVA, sizeof(dotHeader.RVA));
			printf("%s SizeOfRawData         = ", dotHeader.dotName);
			printHexLE("", dotHeader.SizeOfRawData, sizeof(dotHeader.SizeOfRawData));
			printf("%s PointerToRawData      = ", dotHeader.dotName);
			printHexLE("", dotHeader.PointerToRawData, sizeof(dotHeader.PointerToRawData));
			printf("%s PointerToRelocations  = ", dotHeader.dotName);
			printHexLE("", dotHeader.PointerToRelocations, sizeof(dotHeader.PointerToRelocations));
			printf("%s PointerToLineNumbers  = ", dotHeader.dotName);
			printHexLE("", dotHeader.PointerToLineNumbers, sizeof(dotHeader.PointerToLineNumbers));
			printf("%s NumberOfRelocations   = ", dotHeader.dotName);
			printHexLE("", dotHeader.NumberOfRelocations, sizeof(dotHeader.NumberOfRelocations));
			printf("%s NumberOfLineNumbers   = ", dotHeader.dotName);
			printHexLE("", dotHeader.NumberOfLineNumbers, sizeof(dotHeader.NumberOfLineNumbers));
			printf("%s Characteristics       = ", dotHeader.dotName);
			printHexLE("", dotHeader.Characteristics, sizeof(dotHeader.Characteristics));
		}
		printf("---END PE HEADER---\n");
		fclose(inputFile);
	}

	else{
		printf("Arguments Incorrect or Unknown Error.\n");
		help();
	}

	return 0;
}
