#include <stdio.h>
#include <windows.h>

int main(){
	static int addr;
	static HINSTANCE dllHandle;
	static unsigned char c[4];
	static unsigned char d[4];
	static int l;
	static int n[8] = {0, 0, 0, 0, 0, 0, 0, 0};
	static int iter = 0;
	for(iter = 0; iter <= 1000; iter++){
		dllHandle = LoadLibraryA("aeinv.dll");
		addr = (int)GetProcAddress(dllHandle, "CollectMatchingInfo");
		FreeLibrary(dllHandle);
		c[0] = (addr >> 24) & 0xFF;
		c[1] = (addr >> 16) & 0xFF;
		c[2] = (addr >> 8) & 0xFF;
		c[3] = addr & 0xFF;

		dllHandle = LoadLibraryA("aeinv.dll");
		addr = (int)GetProcAddress(dllHandle, "CollectMatchingInfo");
		FreeLibrary(dllHandle);
		d[0] = (addr >> 24) & 0xFF;
		d[1] = (addr >> 16) & 0xFF;
		d[2] = (addr >> 8) & 0xFF;
		d[3] = addr & 0xFF;

		static int i = 0;
		if ((c[0] & 0xF0) != (d[0] & 0xF0)){
			n[0] = 1;
		}
		if ((c[0] & 0x0F) != (d[0] & 0x0F)){
			n[1] = 1;
		}
		//-------
		if ((c[1] & 0xF0) != (d[1] & 0xF0)){
			n[2] = 1;
		}
		if ((c[1] & 0x0F) != (d[1] & 0x0F)){
			n[3] = 1;
		}
		//---------
		if ((c[2] & 0xF0) != (d[2] & 0xF0)){
			n[4] = 1;
		}
		if ((c[2] & 0x0F) != (d[2] & 0x0F)){
			n[5] = 1;
		}
		//--------
		if ((c[3] & 0xF0) != (d[3] & 0xF0)){
			n[6] = 1;
		}
		if ((c[3] & 0x0F) != (d[3] & 0x0F)){
			n[7] = 1;
		}
	}

	static int k = 0;
	printf("Flipped Nibbles: ");
	for (k = 0; k < 8; k++){
			if(k ==0){l=0;}
			printf("%d", n[k]);
			if (n[k] == 1){
				l++;
			}
	}
	printf("\n");
	printf("Entropy: %dbit\n", l*4);
	return 0;
}
