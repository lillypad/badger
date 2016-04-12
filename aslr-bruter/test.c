#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <libgen.h>
int main(int argc, char *argv[]){
	unsigned char test[4] = {'\xAA', '\xAA', '\xAA', '\xAA'};
	unsigned char nibble1;
	unsigned char nibble2;
	int n[8] = { 0, 0, 0, 0 ,0 ,0, 0, 0};
	int i, j, k, l, m;
	int addr;
	unsigned char c[4];
	printf("0x%x\n",(int)GetProcAddress(LoadLibraryA(argv[1]), argv[2]));
	for (m = 0; m < atoi(argv[3]); m++){
		for (i = 0; i <= 3; i++){
			addr = (int)GetProcAddress(LoadLibraryA(argv[1]), argv[2]);
			c[0] = (addr >> 24) & 0xFF;
			c[1] = (addr >> 16) & 0xFF;
			c[2] = (addr >> 8) & 0xFF;
			c[3] = addr & 0xFF;

			nibble1 = (c[i] & 0xF0);
			nibble2 = (c[i] & 0x0F);

			addr = (int)GetProcAddress(LoadLibraryA(argv[1]), argv[2]);
			c[0] = (addr >> 24) & 0xFF;
			c[1] = (addr >> 16) & 0xFF;
			c[2] = (addr >> 8) & 0xFF;
			c[3] = addr & 0xFF;

			if (i == 2){c[i] = '\xd2';}
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
