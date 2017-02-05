#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef unsigned char uint8_t;
//
//	File:	code2x.c: ASCII码字符串到十六进制以及二进制字符串的转换实现
//

/*
*功能：实现一个十六进制字符到十六进制数的转换
*参数：ch：指定十六进制字符
*返回：uint8_t
*/
uint8_t asc_to_hex(const char ch)
{
	if (ch >= '0' && ch <= '9')  //数字0~9
	{
		return (ch - 0x30);
	}
	else
	{
		if (ch >= 'A' && ch <= 'F')  //大写字母A~F
		{
			return (ch - 0x37);
		}
		else if (ch >= 'a' && ch <= 'f') //小写字母a~f
		{
			return ch - 0x57;
		}
		else
		{
			return 0xFF;
		}
	}
}

/*
*功能：实现一个十六进制数到十六进制大写字符的转换
*参数：hex：指定十六进制数
*返回：char
*/
char hex_to_asc(uint8_t hex)
{
	if(hex < 10)
	{
		return hex + '0';
	}
	else if(hex < 16)
	{
		return hex + 55;
	}
	else
	{
		return 0;
	}
}
/*
*功能：实现一个二进制字符到二进制制数的转换
*参数：ch：指定二进制字符
*返回：uint8_t
*/
uint8_t asc_to_bin(const char ch)
{
	if (ch == '0') {
		return 0;
	}
	else if (ch == '1') {
		return 1;
	}
	else return -1;
}

/*
*功能：实现ASCII码字符串到十六进制字符串的转换
*参数：src:需要转换的ASEII码字符串
*返回：指向转换后十六进制字符串区域的指针
*/
char *ascs_to_hexs(const char *src)
{
	if (src == NULL) {
		return NULL;
	}

	int datasize = 0, buffsize = 0;
	char *dst = NULL;

	datasize = strlen(src);


	buffsize = 2 * datasize;	//按照GBK编码，字符串转十六进制长度会变成原来两倍

	dst = (char *)malloc(sizeof(char) * buffsize + 1);
	memset(dst,0,sizeof(char) * buffsize + 1);
	if (dst != NULL)
	{
		for (int i = 0; i < datasize; i++)
		{
			sprintf(dst + i * 2, "%02x", (unsigned char)src[i]);
		}
		return dst;
	}
	else return NULL;
}

/*
*功能：实现十六进制字符串到二进制字符串的转换
*参数：src:需要转换的十六进制字符串
*返回：指向转换后二进制字符串区域的指针
*/
char *hexs_to_bins(const char *src)
{
	if (src == NULL || (strlen(src) % 2 != 0)) {
		return NULL;
	}

	int datasize = 0, buffsize = 0;
	uint8_t n, nhex;

	char *dst;

	datasize = strlen(src);
	buffsize = 4 * datasize;	//十六进制转二进制长度会变成原来四倍

	dst = (char *)malloc(sizeof(char)*buffsize + 1);
	memset(dst, 0, sizeof(char)*buffsize + 1);

	dst[buffsize + 1] = '\0';	//结尾添加结束符

	if (dst != NULL)
	{
		for (int i = 0; 0 != src[i]; i++)
		{
			//转换高四位
			nhex = 0;
			n = asc_to_hex(src[i++]);
			if (n == 0xFF)
			{
				return NULL;
			}
			nhex = n << 4;
			
			//转换低四位
			n = asc_to_hex(src[i]);
			if (n == 0xFF)
			{
				return NULL;
			}
			nhex |= n;

			//储存在目的数组
			for (int j = 0; j < 8; j++)
			{
				dst[((i-1)/2)*8+j] = ((nhex & (1 << (7 - j))) && 1) + '0';
			}
		}
		return dst;
	}
	else return NULL;
}

/*
*功能：实现二进制字符串到十六进制字符串的转换
*参数：src:需要转换的二进制字符串
*返回：指向转换后十六进制字符串区域的指针
*/
char *bins_to_hexs(const char *src)
{
	if (src == NULL || (strlen(src) % 8 != 0)) {	//每八位转换为一个十六进制数
		return NULL;
	}

	int datasize = 0, buffsize = 0;
	uint8_t n, nbin;

	char *dst;

	datasize = strlen(src);
	buffsize = datasize / 4;	//十六进制转二进制长度会变成原来四分之一

	dst = (char *)malloc(sizeof(char)*buffsize + 1);
	memset(dst, 0, sizeof(char)*buffsize + 1);

	dst[buffsize + 1] = '\0';	//结尾添加结束符

	if (dst != NULL)
	{
		for (int i = 0; 0 != src[i]; i++)
		{
			//转换高四位
			nbin = 0;
			for (int j = 0; j < 4; j++)
			{
				n = asc_to_bin(src[i++]);
				if (n == -1)
				{
					return NULL;
				}
				nbin |= n << (7-j);	//把 0 1 串逐个推入
			}

			//转换低四位
			for (int j = 0; j < 4; j++) 
			{

				n = asc_to_bin(src[i++]);
				if (n == -1)
				{
					return NULL;
				}
				nbin |= n << (3-j);
			}

			//储存在目的数组

			sprintf(dst + (((i / 8) - 1)*2), "%x", nbin);

			i--;	//转换低四位时i多进一位，减去
		}
		return dst;
	}
	else return NULL;
}

/*
*功能：实现十六进制字符串到ASCII字符串的转换
*参数：src:需要转换的十六进制字符串
*返回：指向转换后ASCII码字符串区域的指针
*/
char *hexs_to_ascs(const char *src)
{
	if (src == NULL || (strlen(src) % 2 != 0)) {	//GBK编码两位及以上表示一个字符
		return NULL;
	}

	int datasize = 0, buffsize = 0, tmp = 0, i = 0;
	char *dst = NULL;

	datasize = strlen(src);
	buffsize = datasize / 2;	//GBK编码，十六进制转字符长度减一半


	dst = (char *)malloc(sizeof(char)*buffsize + 1);
	memset(dst, 0, sizeof(char) * buffsize + 1);

	if (dst != NULL)
	{
		for (i = 0; i < buffsize; i++)	//i应该到datasize/2 = buffssize结束
		{
			sscanf(src + i*2, "%2x", &tmp);
			dst[i] = (char)tmp;
		}

		return dst;
	}
	else return NULL;
}

char *digit_to_hexs(const int num, const int len)
{
	char *hexstr = (char *)malloc(sizeof(char) * len);
	memset(hexstr, 0, len);

	snprintf(hexstr, len, "%x", num);	//把int型数据以十六进制打印进hexstr字符串缓冲区

	return hexstr;
}
