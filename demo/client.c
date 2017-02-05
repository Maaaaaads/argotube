#include "../library/hsocket.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, const char *argv[])
{
    if (argc != 6)
    {
        printf("usage:%s src_ip src_port dst_ip dst_port data\n", argv[0]);
        exit(1);
    }
    /* 发送ip_tcp报文 */
    send_msg(argv[1], atoi(argv[2]), argv[3], atoi(argv[4]), argv[5]);
    
    return 0;
}