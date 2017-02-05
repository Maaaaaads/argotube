#ifndef OPENDES_H
#define OPENDES_H
#include "ascs2std.h"
#include "code2x.h"
///
///	File:	opendes.h:  functions about des encrypt and decrypt
///
char *openssl_des(const char *src, const char *key, int enc); //main function
char *DES_encrypt(const char *src, const char *key); //encrypt function
char *DES_decrypt(const char *src, const char *key); //decrypt function

#endif // !OPENDES_H