#ifndef HSOCKET_H
#define HSOCKET_H

#include "headers.h"

/**
 * File:hsocket.h :一些raw socket 的函数封装的声明
 */

typedef struct
{
	int frag_id;
	unsigned int data;
}datarray;	//接受信息的结构体缓冲区,frag_id是数据包编号,data是seq位信息.

void err_exit(const char *err_msg);
void send_t(const char *src_ip,const int src_port, const char *dst_ip,const int dst_port, const char *data);
void send_msg(const char *src_ip,const int src_port, const char *dst_ip,const int dst_port, const char *data);
int handshake(const char *src_ip,const int src_port, const char *dst_ip,const int dst_port);
void listen_msg(const int port);	//监听特定端口的消息
void print_msg(const char *src_ip, datarray *data);	//打印消息并清空缓冲区
void send_back(const char *src_ip,const int src_port, const char *dst_ip,const int dst_port, int order);

#endif	//!HSOCKET_H