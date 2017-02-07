#include "../kernel/encoder/code2x.h"
#include "../kernel/string/hexstok.h"
#include "../kernel/crypt/opendes.h"
#include "hsocket.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>

/**
 * File: hsocket.c :一些raw socket 的函数封装的实现
 */

/**
 * err_exit()
 * 打印错误信息并退出
 * @param err_msg 出错的具体调用
 */
void err_exit(const char *err_msg)
{
    perror(err_msg);
    exit(1);
}

/**
 * send_t()
 * 用于发送隐蔽信息
 * @param src_ip   可伪造的源IP地址
 * @param src_port 源端口号
 * @param dst_ip   目标IP地址
 * @param dst_port 目标端口
 * @param data     要发送的字节串信息
 */
void send_t(const char *src_ip,const int src_port, const char *dst_ip,const int dst_port, const char *data)
{
    iphd *ip_header;
    tcphd *tcp_header;
    struct sockaddr_in dst_addr;
    char *frag = NULL;                                          //分片指针
    h_data hdata;                                               //实例化一个隐蔽信息结构体
    int failed = 0, i = 1, mdata_len;//failed_t = 0 
    pseudohdr pseudoheader;                                     //TCP伪首部

    socklen_t sock_addrlen = sizeof(struct sockaddr_in);

    int ip_packet_len;                                          //总的数据包首部+数据的长度
    char msg_buf[IP_TCP_HEADER_LEN + MIX_DATA_LEN];

    int sockfd, ret_len, on = 1, id = 1;                        //id用于信息分割后的分片重组，填充在ip首部的id位
    char *hexstr = NULL;                                        //16进制字符串指针
    // char recv_buf[IP_TCP_BUFF_SIZE];                            //接收原始数据包的缓冲区
    
    srand((unsigned)time(NULL));                                //用时间做种，每次产生随机数不一样

    //装填目标的基本信息
    memset(&dst_addr, 0, sock_addrlen);
    dst_addr.sin_family = AF_INET;
    dst_addr.sin_addr.s_addr = inet_addr(dst_ip);
    dst_addr.sin_port = htons(dst_port);

    //创建tcp原始套接字
    if ((sockfd = socket(AF_INET , SOCK_RAW, IPPROTO_TCP)) == -1)
    {
        err_exit("socket()");
    }

    //开启IP_HDRINCL，自定义IP首部
    if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) == -1)
    {
        err_exit("setsockopt()");
    }


    //初始化IP首部
    ip_header = init_ip_header(src_ip, dst_ip);

    if(ip_header == NULL)
    {
    	err_exit("ip_header()");
    }
    //初始化TCP首部
    tcp_header = init_tcp_header(src_port, dst_port);

    if(tcp_header == NULL)
    {
    	err_exit("tcp_header()");
    }

    //获取源数据的十六进制表示的字符串指针
    hexstr = ascs_to_hexs(data);
    //调用字符串分割函数获取第一个分片
    frag = hexstok(hexstr, i, 8);
    //当分片非空一直获取分片
    while(frag != NULL)
	{
        //初始化隐蔽信息结构体，并获取随机生产的迷惑信息的长度，用于后期组包
		mdata_len = init_hdata(frag, &hdata, id);
        ip_packet_len = IP_TCP_HEADER_LEN + mdata_len;

        //填充IP、TCP首部自定义的隐蔽信息
		fill_ip_header(ip_header, ip_packet_len, hdata.frag_id);
		fill_tcp_header(ip_header, tcp_header, hdata.t_data, pseudoheader);

        //组包
        memset(msg_buf, 0, ip_packet_len);
        memcpy(msg_buf, ip_header, IP_HEADER_LEN);
        memcpy(msg_buf + IP_HEADER_LEN, tcp_header, TCP_HEADER_LEN);
		memcpy(msg_buf + IP_TCP_HEADER_LEN, hdata.m_data, mdata_len);

		//调用发送函数
		ret_len = sendto(sockfd, msg_buf, ip_packet_len, 0, (struct sockaddr *)&dst_addr, sock_addrlen);
		if (ret_len > 0)
		{
   //          //发送成功
			// printf("Frag %d sent!\n\n", hdata.frag_id);
		}
		else //发送失败
		{
			printf("Frag %d sendto() failed\n", hdata.frag_id);
			failed = 1;
		}

		i+=8;     //因为32bit / 4 == 8
        id++;   //分片序号增加
		free(frag);   //先释放frag不然会造成大量内存泄露
        frag = hexstok(hexstr, i, 8);   //继续获取分片

	}

    //如果发送过程没有出现错误，告知目标发送完毕
	if(!failed)
	{
        //初始化告知包，返回迷惑信息长度
		mdata_len = init_hdata("ffffffff", &hdata, id);
	    ip_packet_len = IP_TCP_HEADER_LEN + mdata_len;
	        
        //填充OVER信息
		fill_ip_header(ip_header, ip_packet_len, hdata.frag_id);
		fill_tcp_header(ip_header, tcp_header, OVER, pseudoheader);

        //组建OVER包
        memset(msg_buf, 0, ip_packet_len);
        memcpy(msg_buf, ip_header, IP_HEADER_LEN);
        memcpy(msg_buf + IP_HEADER_LEN, tcp_header, TCP_HEADER_LEN);
		memcpy(msg_buf + IP_TCP_HEADER_LEN, hdata.m_data, mdata_len);
		//调用发送函数
		ret_len = sendto(sockfd, msg_buf, ip_packet_len, 0, (struct sockaddr *)&dst_addr, sock_addrlen);
		if(ret_len > 0)
		{

			// while (1)
   //  		{
	  //       	memset(recv_buf, 0, IP_TCP_BUFF_SIZE);
	  //       	ret_len = recv(sockfd, recv_buf, IP_TCP_BUFF_SIZE, 0);
	  //       	if (ret_len > 0)
	  //       	{
	  //       		ip_header = (struct ip *)recv_buf;
	  //           	/* 取出tcp首部 */
		 //            tcp_header = (struct tcphdr *)(recv_buf + IP_HEADER_LEN);

   //                  //接收目标机器的数据包
		 //            if(!strcmp(inet_ntoa(ip_header->ip_src), dst_ip) && ntohs(tcp_header->dest) == src_port)
		 //            {
		 //                if(tcp_header -> seq == CONFIRM)
		 //                {
		 //                	break;
		 //                }
		 //                else if (tcp_header -> seq == DECLINE)
		 //                {
		 //                	failed_t = 1;
		 //                	break;
		 //                }
		 //            }

   //          	}
   //      	}
        	// if(!failed_t)
        	// {
        		printf("Message reached!\n");
        	// }
        	// else
        	// {
        	// 	printf("Server declined for some unkown reasons!\n");
        	// }
		}
	}
	else //如果中间有分片未发送成功，告知目标丢弃此次信息
	{
        //初始化告知包，返回迷惑信息长度
        mdata_len = init_hdata("ffffffff", &hdata, id);
        ip_packet_len = IP_TCP_HEADER_LEN + mdata_len;
            
        //填充OVER信息
        fill_ip_header(ip_header, ip_packet_len, hdata.frag_id);
        fill_tcp_header(ip_header, tcp_header, BROKEN, pseudoheader);

        //组建OVER包
        memset(msg_buf, 0, ip_packet_len);
        memcpy(msg_buf, ip_header, IP_HEADER_LEN);
        memcpy(msg_buf + IP_HEADER_LEN, tcp_header, TCP_HEADER_LEN);
        memcpy(msg_buf + IP_TCP_HEADER_LEN, hdata.m_data, mdata_len);
        //调用发送函数
        ret_len = sendto(sockfd, msg_buf, ip_packet_len, 0, (struct sockaddr *)&dst_addr, sock_addrlen);
        
        if(ret_len <= 0)
        {
            err_exit("Broken sendto():");
        }

		err_exit("sendto()");
	}

    close(sockfd);
    free(hexstr);
    free(ip_header);
    free(tcp_header);
}

/**
 * send_msg()
 * 调用send_t()发送信息，存在握手过程
 * @param src_ip   [description]
 * @param src_port [description]
 * @param dst_ip   [description]
 * @param dst_port [description]
 * @param data     [description]
 */
void send_msg(const char *src_ip,const int src_port, const char *dst_ip,const int dst_port, const char *data)
{
	int recv;  //接收握手结果
    char *encdata = NULL;

	recv = handshake(src_ip, src_port, dst_ip, dst_port);

    //握手成功
	if(recv == CONFIRM)
	{
        //des加密信息
        encdata = DES_encrypt(data, KEY);
        //发送消息
		send_t(src_ip, src_port, dst_ip, dst_port, encdata);

        free(encdata);
	}
	else if(recv == DECLINE)   //握手失败
	{
		printf("Unkown host!\n");
	}
}

/**
 * print_msg()
 * 格式化打印数据缓冲区的数据
 * @param src_ip 源IP
 * @param data   数据缓冲区
 */
void print_msg(const char *src_ip, datarray *data)
{

    if(src_ip == NULL || data == NULL)
    {
        err_exit("print_msg():");
    }

    char hex_msg[DATA_LEN] = {0};   //消息的16进制缓冲区
    char *tmp = NULL;   //临时存放分片
    char *t_msg = NULL; //ASCII信息
    char *dec_msg = NULL; //解密后的信息

    //循环读取数据缓冲区的数据
    for(int i = 0; data[i].frag_id > 0; i++)
    {
        //SEQ位的10进制转换为16进制字符串
        tmp = digit_to_hexs(data[i].data, FRAG_SIZE);
        //字符串连接
        strncat(hex_msg, tmp, strlen(tmp));
        free(tmp);
    }

    //16进制字符串转化为ASCII信息
    t_msg = hexs_to_ascs(hex_msg);
    dec_msg = DES_decrypt(t_msg, KEY);
    //格式化打印
    printf("%s:%s\n", src_ip, dec_msg);
    free(t_msg);
    free(dec_msg);
}

/**
 * [listen_msg description]
 * 监听本机指定端口经过的数据包并打印
 * @param port 监听的端口号
 */
void listen_msg(const int port)
{
    iphd *ip_header;
    tcphd *tcp_header;
    int recvfd, ret_len, i = 0;
    datarray data[DATA_LEN / 4 + 1]={0};    //32bits == 4bytes，接收隐蔽数据的缓冲区, 接收到的是32位无符号整数形式
    char src_ip[20];                    //源IP接收缓冲区
    char recv_buf[IP_TCP_BUFF_SIZE];    //接收源数据包的缓冲区

    if ((recvfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) == -1)
    {
        err_exit("socket()");
    }

    printf("Listen...\n");

    //无限循环接收消息
    while (1)
    {
        memset(recv_buf, 0, IP_TCP_BUFF_SIZE);
        ret_len = recv(recvfd, recv_buf, IP_TCP_BUFF_SIZE, 0);
        if (ret_len > 0)
        {
            ip_header = (struct ip *)recv_buf;
            /* 取出tcp首部 */
            tcp_header = (struct tcphdr *)(recv_buf + IP_HEADER_LEN);

            if(ntohs(tcp_header->dest) == port) //监听特定的端口
            {
                //如果是客户机请求链接的情景
                if(tcp_header -> seq == ASK)
                {
                	memset(src_ip, 0, 20);
                    //把源IP打印到src_ip缓冲区
                    snprintf(src_ip, sizeof(src_ip), "%s", inet_ntoa(ip_header -> ip_src));
                    //if(istrusthost(host)),发送CONFIRM信息以确认握手过程
                    send_back(inet_ntoa(ip_header->ip_dst), ntohs(tcp_header->dest), src_ip, ntohs(tcp_header->source), CONFIRM);
                }
                else if(tcp_header -> seq == OVER)  //信息分片传输完毕的情景
                {
                	memset(src_ip, 0, 20);
                    //把源IP打印到src_ip缓冲区
                    snprintf(src_ip, sizeof(src_ip), "%s", inet_ntoa(ip_header -> ip_src));
                    //打印消息
                    print_msg(src_ip, data);
                    //清空数据缓冲区
                    memset(data, 0, DATA_LEN / 4 + 1);
                    memset(src_ip, 0, 20);
                    //接受数据分片的序号清零
                    i = 0;
                    //send_back(inet_ntoa(ip_header->ip_dst), ntohs(tcp_header->dest), inet_ntoa(ip_header->ip_src), ntohs(tcp_header->source), CONFIRM);
                }
                else if(tcp_header -> seq == BROKEN)
                {
                     //清空数据缓冲区
                    memset(data, 0, DATA_LEN / 4 + 1);
                    memset(src_ip, 0, 20);
                    //接受数据分片的序号清零
                    i = 0;
                }
                else    //只剩下是分片到达
                {
                    //避免自身测试时候发生错误，即接受了自己发送的指令
                    if(tcp_header -> seq == CONFIRM || tcp_header -> seq == DECLINE)
                    {
                        continue;
                    }
                    //数据缓冲区累加
                    data[i].frag_id = ip_header -> ip_id;
                    data[i].data = tcp_header -> seq;
                    i++; //序号
                }

                // printf("from ip:%s\n", inet_ntoa(ip_header->ip_src));
                // printf("from port:%d\n", ntohs(tcp_header->source));

            }
        }
    }
    
    close(recvfd);
}

/**
 * send_back()
 * 用于回显给客户机的一些指令与信息
 * @param src_ip   源IP地址，可伪造
 * @param src_port 源端口号
 * @param dst_ip   目标IP地址
 * @param dst_port 目标端口号
 * @param order    返回的信息类型
 */
void send_back(const char *src_ip,const int src_port, const char *dst_ip,const int dst_port, int order)
{
    iphd *ip_header;
    tcphd *tcp_header;
    struct sockaddr_in dst_addr;
    h_data hdata;   //实例化一个隐蔽信息结构
    int mdata_len;  //迷惑信息的长度
    pseudohdr pseudoheader; //TCP伪首部，用于校验和计算

    socklen_t sock_addrlen = sizeof(struct sockaddr_in);
    
    int ip_packet_len;                //总的数据包首部+数据的长度
    char msg_buf[IP_TCP_HEADER_LEN + MIX_DATA_LEN];

    int sockfd, on = 1, id = 1;  //id用于信息分割后的分片重组，填充在ip首部的id位
    int ret_len;     

    srand((unsigned)time(NULL)); //用时间做种，每次产生随机数不一样


    //填充目标机器的基本信息
    memset(&dst_addr, 0, sock_addrlen);
    dst_addr.sin_family = AF_INET;
    dst_addr.sin_addr.s_addr = inet_addr(dst_ip);
    dst_addr.sin_port = htons(dst_port);

    //创建TCP原始套接字
    if ((sockfd = socket(AF_INET , SOCK_RAW, IPPROTO_TCP)) == -1)
    {
        err_exit("socket()");
    }

    //开启IP_HDRINCL，自定义IP首部
    if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) == -1)
    {
        err_exit("setsockopt()");
    }

    //初始化IP首部
    ip_header = init_ip_header(src_ip, dst_ip);

    if(ip_header == NULL)
    {
        err_exit("ip_header()");
    }
    //初始化TCP首部
    tcp_header = init_tcp_header(src_port, dst_port);

    if(tcp_header == NULL)
    {
        err_exit("tcp_header()");
    }

    mdata_len = init_hdata("ffffffff", &hdata, id); //此函数初始化隐蔽信息结构体，并且返回产生的迷惑信息的长度
    ip_packet_len = IP_TCP_HEADER_LEN + mdata_len; //加1加的是最后的结束符


    //填充IP、TCP首部的自定义信息        
    fill_ip_header(ip_header, ip_packet_len, hdata.frag_id);
    fill_tcp_header(ip_header, tcp_header, order, pseudoheader);

    //开始组建要发送的原始IP数据包
    memset(msg_buf, 0, ip_packet_len);
    memcpy(msg_buf, ip_header, IP_HEADER_LEN);
    memcpy(msg_buf + IP_HEADER_LEN, tcp_header, TCP_HEADER_LEN);
    memcpy(msg_buf + IP_TCP_HEADER_LEN, hdata.m_data, mdata_len);
    
    //组包完成，调用发送函数
    ret_len = sendto(sockfd, msg_buf, ip_packet_len, 0, (struct sockaddr *)&dst_addr, sock_addrlen);
    if(ret_len <= 0)
    {
        close(sockfd);
        free(tcp_header);
        free(ip_header);
        err_exit("order sendto():");
    }

    //后续处理，释放资源
    close(sockfd);
    free(tcp_header);
    free(ip_header);
}

/**
 * handshake()
 * 客户机与服务器的握手函数
 * @param  src_ip   可伪造的本机IP
 * @param  src_port 本机发送端口
 * @param  dst_ip   欲握手的目标服务器IP
 * @param  dst_port 服务器端口
 * @return          返回握手结果
 */
int handshake(const char *src_ip,const int src_port, const char *dst_ip,const int dst_port)
{
    iphd *ip_header;
    tcphd *tcp_header;
    struct sockaddr_in dst_addr;
    h_data hdata;   //实例化一个隐蔽信息
    int mdata_len, result;
    pseudohdr pseudoheader; //TCP伪首部

    socklen_t sock_addrlen = sizeof(struct sockaddr_in);
    
    int ip_packet_len;                //总的数据包首部+数据的长度
    char msg_buf[IP_TCP_HEADER_LEN + MIX_DATA_LEN];

    int sockfd, recvfd, on = 1, id = 1;  //id用于信息分割后的分片重组，填充在ip首部的id位,从1开始是因为0是默认的意思
    int ret_len;
    char recv_buf[IP_TCP_BUFF_SIZE];                
    pid_t fpid;
    int fd[2]; //管道通信
    char pipe_buf[10];

    if(pipe(fd) < 0)
    {
        err_exit("pipe():");
    }
    //fork一个监听进程
    fpid = fork();
    if(fpid < 0)
    {
        err_exit("fork():");
    }
    else if(fpid == 0) //子进程
    {
        //创建监听套接字
        if ((recvfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) == -1)
        {
            err_exit("socket()");
        }

        while (1)
        {
            memset(recv_buf, 0, IP_TCP_BUFF_SIZE);
            ret_len = recv(recvfd, recv_buf, IP_TCP_BUFF_SIZE, 0);
            if (ret_len > 0)
            {
                //取出IP、TCP首部
                ip_header = (struct ip *)recv_buf;
                tcp_header = (struct tcphdr *)(recv_buf + IP_HEADER_LEN);

                //如果来源的信息的IP和端口号对应
                if(!strcmp(inet_ntoa(ip_header->ip_src), dst_ip) && ntohs(tcp_header->dest) == src_port)
                {
                    if(tcp_header -> seq == CONFIRM)
                    {
                        sprintf(pipe_buf, "%s", "CONFIRM");

                        if(write(fd[1], pipe_buf, sizeof(pipe_buf)) < 0)
                        {
                        	err_exit("write():");
                        }

                        close(recvfd);
                        exit(0);
                    }
                    else if(tcp_header -> seq == DECLINE)
                    {
                        sprintf(pipe_buf, "%s", "DECLINE");

                        if(write(fd[1], pipe_buf, sizeof(pipe_buf)) < 0)
                        {
                        	err_exit("write():");
                        }

                        close(recvfd);
                        exit(0);
                    }
                    else
                    {
                        continue;
                    }
                }

            }
        }
    }
    else    //父进程
    {
        //填充目标服务器信息
        memset(&dst_addr, 0, sock_addrlen);
        dst_addr.sin_family = AF_INET;
        dst_addr.sin_addr.s_addr = inet_addr(dst_ip);
        dst_addr.sin_port = htons(dst_port);

        //创建TCP原始套接字
        if ((sockfd = socket(AF_INET , SOCK_RAW, IPPROTO_TCP)) == -1)
        {
            err_exit("socket()");
        }

        //开启IP_HDRINCL，自定义IP首部
        if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) == -1)
        {
            err_exit("setsockopt()");
        }

        //初始化IP首部
        ip_header = init_ip_header(src_ip, dst_ip);

        if(ip_header == NULL)
        {
            err_exit("ip_header()");
        }
        //初始化TCP首部
        tcp_header = init_tcp_header(src_port, dst_port);

        if(tcp_header == NULL)
        {
            err_exit("tcp_header()");
        }

        srand((unsigned)time(NULL)); //用时间做种，每次产生随机数不一样

        mdata_len = init_hdata("ffffffff", &hdata, id);
        ip_packet_len = IP_TCP_HEADER_LEN + mdata_len;
            
        //装填IP、TCP首部的必要信息，此时为握手信息ASK
        fill_ip_header(ip_header, ip_packet_len, hdata.frag_id);
        fill_tcp_header(ip_header, tcp_header, ASK, pseudoheader);


        //组包
        memset(msg_buf, 0, ip_packet_len);
        memcpy(msg_buf, ip_header, IP_HEADER_LEN);
        memcpy(msg_buf + IP_HEADER_LEN, tcp_header, TCP_HEADER_LEN);
        memcpy(msg_buf + IP_TCP_HEADER_LEN, hdata.m_data, mdata_len);
        //调用发送函数sendto();
        ret_len = sendto(sockfd, msg_buf, ip_packet_len, 0, (struct sockaddr *)&dst_addr, sock_addrlen);
        if(ret_len > 0)
        {
            //读管道数据
            if(read(fd[0],pipe_buf,sizeof(pipe_buf)) < 0)
            {
            	err_exit("read():");
            }
            
            //失败
            if(!strcmp(pipe_buf, "DECLINE"))
            {
                close(sockfd);
                free(tcp_header);
                free(ip_header);
                //返回失败
                result = DECLINE;
            }
            else if(!strcmp(pipe_buf, "CONFIRM"))    //成功
            {
                close(sockfd);
                free(tcp_header);
                free(ip_header);
                //返回成功
                result = CONFIRM;
            }
        }
    }

    return result;
}
