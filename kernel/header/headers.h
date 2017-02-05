#ifndef HEADERS_H
#define HEADERS_H

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

/**
 * File :headers.h :IP、TCP首部的自定义函数，以及必要的宏与结构体
 */
#define PORT 6666
#define OVER 0xffff
#define ASK 0x0f0f
#define CONFIRM 0xf0f0
#define DECLINE 0xff00
#define BROKEN 0x00ff
#define KEY "yourname"

//盐信息长度
#define MIX_DATA_LEN 1400
//每次发送的数据长度限制
#define DATA_LEN 140
//每个分片的大小限制
#define FRAG_SIZE 9
//ip首部长度
#define IP_HEADER_LEN sizeof(struct ip)
//tcp首部长度
#define TCP_HEADER_LEN sizeof(struct tcphdr)
//ip首部 + tcp首部长度
#define IP_TCP_HEADER_LEN IP_HEADER_LEN + TCP_HEADER_LEN
//ip首部 + tcp首部 + 数据缓冲区大小
#define IP_TCP_BUFF_SIZE IP_TCP_HEADER_LEN + MIX_DATA_LEN

//隐蔽信息的结构体
typedef struct
{
	int frag_id;
	unsigned int t_data;               			//填充于tcp seq位的信息，必须为32位，不足用0填充
	char m_data[MIX_DATA_LEN];                 //附加于ip tcp首部后面的迷惑信息
}h_data;                                     //隐蔽信息结构体

//IP、TCP首部
typedef struct ip iphd;
typedef struct tcphdr tcphd;

//计算TCP校验和字段时需要加上伪首部
typedef struct
{
    struct in_addr saddr;
    struct in_addr daddr;
    u_char zero;
    u_char protocol;
    u_short length;
    struct tcphdr tcpheader;
}pseudohdr; 


int init_hdata(const char *data, h_data *hdata, int id);

iphd *init_ip_header(const char *src_ip, const char *dst_ip);
void fill_ip_header(iphd *ip_header, int ip_packet_len, int id);

tcphd *init_tcp_header(int src_port, int dst_port);
void fill_tcp_header(iphd *iphdr, tcphd *tcp_header, unsigned int t_data, pseudohdr pseudoheader);


u_short checksum(u_short *data, u_short length);

#endif	//!HEADERS_H