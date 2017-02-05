#include <stdio.h>
#include <unistd.h>
int main()
{
	int filedes[2];
	char buf[10];
	pipe(filedes);
	if(fork() ==0)
	{
		sprintf(buf,"%s","123");
		write(filedes[1],buf,sizeof(buf));
	}
	else
	{
		read(filedes[0],buf,sizeof(buf));
		printf("%s\n",buf);
	}
	return 0;
}