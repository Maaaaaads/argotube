
#include "headers.h"
#include <time.h>
#include <stdlib.h>
#include <string.h>

/**
 * File : headers.c ：IP、TCP首部操作的函数的实现
 */

/**
 * checksum()
 * 计较校验和
 * @param  data   欲计算的数据
 * @param  length 长度
 * @return        返回计算结果
 */
u_short checksum(u_short *data, u_short length)
{
    register long value;
    u_short i;
    for(i = 0; i < (length >> 1); i++)
    {
        value += data[i];
    }
    if(1 == (length &1))
    {
        value += (data[i] << 8);
    }
    value = (value & 65535) + (value >> 16);
    return (~value);
}


/**
 * init_hdata()
 * 初始化隐蔽信息结构体
 * @param  data  数据
 * @param  hdata 隐蔽信息结构体的一个实例化
 * @param  id    分片序号
 * @return       返回迷惑信息的长度
 */
int init_hdata(const char *data, h_data *hdata, int id)
{
	if(data == NULL || hdata == NULL)
	{
		return 0;
	}

    //迷惑信息缓冲区
	char mix_data[MIX_DATA_LEN];

    //生成的迷惑信息的长度随机
	int time = rand() % MIX_DATA_LEN;

	for (int i = 0; i < time; i++)
	{
		mix_data[i] = rand() % 95 + 32;  //产生32-127的随机数，就是可见字符
	}
	mix_data[time] = '\0'; //添加结束符

    //填充隐蔽信息以及迷惑信息
	hdata -> t_data = strtol(data, NULL, 16);
	strncpy(hdata -> m_data, mix_data, time + 1);
	hdata -> frag_id = id;

    return time + 1;
}


/**
 * init_ip_header()
 * @param  src_ip 源IP地址
 * @param  dst_ip 目标IP地址
 * @return        返回一个IP首部指针
 */
iphd *init_ip_header(const char *src_ip, const char *dst_ip)
{
    iphd *ip_header;

    ip_header = (iphd *)malloc(IP_HEADER_LEN);

    if(ip_header == NULL)
    {
    	return NULL;
    }

    //填充一些无关的信息
	memset(ip_header, 0, IP_HEADER_LEN);

    ip_header->ip_v = IPVERSION;
    ip_header->ip_hl = IP_HEADER_LEN / 4;           //ip首部长度是指占多个32位的数量，4字节=32位，所以除以4
    ip_header->ip_tos = 0;
    ip_header->ip_len = 0;                          //整个IP数据报长度，包括包头后面的数据
	ip_header->ip_id = 0;
    ip_header->ip_off = 0;							//默认DF==1,不分片
    ip_header->ip_ttl = MAXTTL;
    ip_header->ip_p = IPPROTO_TCP;                   //ip包封装的协议类型
    ip_header->ip_src.s_addr = inet_addr(src_ip);    //伪造的源IP地址
    ip_header->ip_dst.s_addr = inet_addr(dst_ip);    //目标IP地址
    ip_header->ip_sum = 0;
    return ip_header;
}

/**
 * fill_ip_header()
 * @param ip_header     IP首部
 * @param ip_packet_len IP包的数据包长度
 * @param id            分片序号
 */
void fill_ip_header(iphd *ip_header, int ip_packet_len, int id)
{
	ip_header->ip_len = ip_packet_len;        //整个IP数据报长度，包括包头后面的数据
	ip_header->ip_id = id;                           //填充要发送的数据分片的序号
}

/**
 * init_tcp_header()
 * 初始化TCP首部，主要填充一些无关信息
 * @param  src_port 源端口
 * @param  dst_port 目标端口
 * @return          返回得到的TCP首部指针
 */
tcphd *init_tcp_header(int src_port, int dst_port)
{
    tcphd *tcp_header;

    //初始化一个TC首部
    tcp_header = (tcphd *)malloc(TCP_HEADER_LEN);

    if(tcp_header == NULL)
    {
    	return NULL;
    }

    //填充无关信息
    memset(tcp_header, 0, TCP_HEADER_LEN);

    tcp_header->source = htons(src_port);   //伪造的端口号
    tcp_header->dest = htons(dst_port);
    tcp_header->doff = sizeof(tcphd) / 4;  //同IP首部一样，这里是占32位的字节多少个
    tcp_header->seq = 0;
    tcp_header->syn = 0;
    tcp_header->check = 0;

    return tcp_header;
}

/**
 * fill_tcp_header()
 * 填充TCP首部的必要信息
 * @param iphdr        IP首部
 * @param tcp_header   TCP首部
 * @param t_data       真实信息，32位信息分片，无符号整数
 * @param pseudoheader TCP伪首部
 */
void fill_tcp_header(iphd *iphdr, tcphd *tcp_header, unsigned int t_data, pseudohdr pseudoheader)
{
	tcp_header->seq = t_data; //填充隐蔽信息

	//填充伪首部信息， 用于计算tcp首部校验和
    memset(&pseudoheader, 0, 12 + TCP_HEADER_LEN);
	pseudoheader.saddr.s_addr = iphdr->ip_src.s_addr; // 伪造的源IP地址
	pseudoheader.daddr.s_addr = iphdr->ip_dst.s_addr; // 目的IP地址
	pseudoheader.protocol = IPPROTO_TCP;
	pseudoheader.length = htons(TCP_HEADER_LEN);
	bcopy((char *)tcp_header, (char *)&pseudoheader.tcpheader, TCP_HEADER_LEN);

	tcp_header->check = checksum((u_short *)&pseudoheader, 12 + TCP_HEADER_LEN);   //填充校验和字段
}


