#ifndef CODE2X_H
#define CODE2X_H

//
//	File:	code2x.h : ASCII码字符串到十六进制以及二进制字符串
//
typedef unsigned char uint8_t;

char hex_to_asc(uint8_t hex);
uint8_t asc_to_hex(const char ch);		//十六进制字符转数字
uint8_t asc_to_bin(const char ch);		//二进制字符转数字
char *ascs_to_hexs(const char *src);	//字符串转十六进制
char *hexs_to_bins(const char *src);	//十六进制转二进制
char *bins_to_hexs(const char *src);	//二进制转十六进制
char *hexs_to_ascs(const char *src);	//十六进制转字符串
char *digit_to_hexs(const int num, const int len);	//整形数据转换十六进制字符串

#endif // !CODE2X_H



