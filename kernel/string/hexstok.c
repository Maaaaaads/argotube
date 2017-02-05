#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
*function: select substrings from source string, from left, cunt chars
*args: src : source string; left : locate; cunt : substring length
* ret:substring
 */
char *hexstok(const char *src, int left, int cunt)
{
	int len = strlen(src), ncunt = cunt, k = 0;
	char *ds = NULL;

	if(left > len)
	{
		return NULL;
	}
	

	ds = (char *)malloc(sizeof(char) * ncunt + 1);
	memset(ds, '0', sizeof(char) * ncunt);

	if(len - left + 1 < cunt)
	{
		for(int i = 0; i < cunt - len + left -1; i++)
		{
			ds[k++] = '0';
		}
	}

	for(int i = 0; i < ncunt; i++)
	{
		ds[k++] = src[left - 1 + i];
	}

	//add eof
	ds[k] = '\0';

	return ds;
}

//usage like :
// int main()
// {
// 	char *str = "1a2b356614562163", *ds = NULL;
// 	int i = 1;
// 	while(hexstok(str, i ,4) != NULL)
// 	{
// 		ds = hexstok(str, i, 4);
// 		printf("%s\n", ds);
// 		i+=4;
// 	}
	
// 	return 0;
// }



