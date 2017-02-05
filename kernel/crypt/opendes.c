#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/des.h>

#include "ascs2std.h"
#include "code2x.h"
///
///     DES-ECB加密 gcc -Wall -O2 -o openssl_des openssl_des.c ascs2std.c code2x.c -lcrypto
///

/*
*function: des-encrypt main function
*args: src:source string key: des-key enc: whether encrypt or decrypt
* ret: a string after encrypt
 */

char *openssl_des(const char *src, const char *key, int enc)
{
	DES_key_schedule ks;
	DES_cblock ky;
	char *dst = NULL, out[8], *tmp = NULL, *stmp = NULL;
	int cunt = 0;
	
	tmp = (char *)malloc(sizeof(char) * 16 + 1);
	if(tmp == NULL)
	{
		return NULL;
	}
	memset(tmp, 0, sizeof(char) * 16 + 1);

	cunt = strlen(src) / 16;
	//根据字符串生成key
	DES_string_to_key(key, &ky);
	
	//设置密码表
	DES_set_key_unchecked(&ky, &ks);
	
	dst = (char *)malloc(sizeof(char) * cunt * 8 + 1);
	if(dst == NULL)
	{
		return NULL;
	}
	memset(dst, 0, sizeof(char) * cunt * 8 + 1);
	
	if(enc == DES_ENCRYPT)
	{
		for(int i = 0; i < cunt; i++)
		{
			memcpy(tmp, src + i * 16, 16);
			tmp[16] = '\0';
			stmp = hexs_to_ascs(tmp);
			// openssl-des main function; mode :ECB
			DES_ecb_encrypt((const_DES_cblock *)stmp, (DES_cblock *)out, &ks, DES_ENCRYPT);
			memcpy(dst + 8 * i, out, 8);
			free(stmp);
		}
	}
	else
	{
		for(int i = 0; i < cunt; i++)
		{
			memcpy(tmp, src + i * 16, 16);
			tmp[16] = '\0';
			stmp = hexs_to_ascs(tmp);
			DES_ecb_encrypt((const_DES_cblock *)stmp, (DES_cblock *)out, &ks, DES_DECRYPT);
			memcpy(dst + 8 * i, out, 8);
			free(stmp);
		}
	}
	free(tmp);
	return dst;
}

/*
*function: return a string after des-encrypt
*args: src:source string key: des-key
* ret: a string after encrypt
 */
char *DES_encrypt(const char *src, const char *key)
{
	char *dst = NULL, *stdhex = NULL, *stdsrc = NULL;

	stdsrc = ascs_to_std(src);
	//get padding data string

	stdhex = ascs_to_hexs(stdsrc);

	dst = openssl_des(stdhex, key, DES_ENCRYPT);

	free(stdhex);
	
	return dst;
}

/*
*function: return a string after des-decrypt
*args: src:source string key: des-key
* ret: a string after decrypt
 */
char *DES_decrypt(const char *src, const char *key)
{
	char *stdsrc = NULL, *dst = NULL, *stdhex = NULL;
	int len = 0;

	stdsrc = ascs_to_std(src);
	
	//get padding data
	stdhex = ascs_to_hexs(stdsrc);

	//des decrypt
	dst = openssl_des(stdhex, key, DES_DECRYPT);

	len = strlen(dst);

	//decode padding
	//
	for (int i = len -1 ; i >= 0; i--)
	{
		if(dst[i] > 0 && dst[i] < 8) //padding data is between 0~8, so cut it.
		{
			continue;
		}
		else
		{
			dst[i + 1]='\0';
			break;
		}
	}

	//free sources
	free(stdhex);
	
	return dst;
}




	
		
	
