#include "../crypt/opendes.h"
#include "../string/hexstok.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
//
//    gcc -Wall -O2 -o des_tok des.c hexs2std.c code2x.c hexstok.c -lcrypto
//
int main()
{
	char *str = "key is your birthday aaa ";
	char *key = "abcdefg";
	char *ds = NULL;
	char *h1 = NULL;
	char *h2 = NULL;
	char *hexstr = NULL;
	int i = 1;

	printf("before encrypt:%d %s\n",strlen(str), str);
	h1 = DES_encrypt(str, key);

	printf("after encrypto:%d %s\n", strlen(h1), h1);
	h2 = DES_decrypt(h1, key);

	printf("after decrypto:%d %s\n" ,strlen(h2), h2);

	hexstr = ascs_to_hexs(h2);
	while(hexstok(hexstr, i ,4) != NULL)
	{
		ds = hexstok(hexstr, i, 4);
		printf("%s\n", ds);
		i+=4;
	}

	free(h1);
	free(h2);
	free(hexstr);
	free(ds);

	
	return 0;
}
