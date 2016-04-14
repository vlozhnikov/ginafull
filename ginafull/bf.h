#pragma once

/*#define bf_Key "PAVEL WINSOCK key for BlowFish encrpyption with a lot of character for better security level - should be impossible to crack!"*/

//extern BYTE nac_printf(CHAR* fmt, ...);

INT BF_set(void);
INT BF_setKey(const BYTE* key);
INT BF_encryptByte(char *ByteArray,int *length);
INT BF_decryptByte(char *ByteArray,int *length);
INT BF_reset(void);
INT BF_isset(void);