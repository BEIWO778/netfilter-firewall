#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <errno.h>  
#include "../filter/fwfilter.h"

ban_status rules;

void printError(char * msg)
{
	printf("%s error %d: %s\n", msg, errno, strerror(errno));
}
void get_status();                              //获得当前防火墙规则函数        
void change_status(int sockfd, socklen_t len);  //改变防火墙规则函数 
void change_ping(int sockfd, socklen_t len);    //改变ping规则函数 
void change_ip(int sockfd, socklen_t len);      //改变ip规则函数 
void change_port(int sockfd, socklen_t len);    //改变端口规则函数 

int main(void)
{
	int sockfd;
	socklen_t len;
	if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) == -1)
		printError("socket");
	else{
		len = sizeof(rules);
		if(getsockopt(sockfd, IPPROTO_IP, NOWRULE, (void *)&rules, &len))
			printError("getsockopt");
		else{
			//打印当前防火墙规则和改变规则菜单 
			while(1){
				get_status();
				change_status(sockfd, len);
			}
		}
	}
	return 0;
}

void get_status() 
{
	printf("\ncurrent firewall status:\n");
	//rules.ping_status为1时禁止ping 
	if(rules.ping_status == 1)
		printf("ban ping\n");
	else
		printf("no ban ping\n");
	//打印当前禁止ip值 
	if(rules.ip_status == 1){
		printf("ban ip:%d.%d.%d.%d\n", 
			(rules.ban_ip & 0x000000ff) >> 0,
			(rules.ban_ip & 0x0000ff00) >> 8,
			(rules.ban_ip & 0x00ff0000) >> 16,
			(rules.ban_ip & 0xff000000) >> 24);
	}else{
		printf("no ban ip\n");
	}
	//打印当前禁止ip值 
	if(rules.port_status == 1)
		printf("ban port:%hu\n", rules.ban_port);
	else
		printf("no ban port\n");
}

void change_status(int sockfd, socklen_t len)
{
	int choice;
	printf("\n1.ping 2.ip 3.port 4.exit");
	printf("\nchange firewall status:\n");
	scanf("%d", &choice);
	switch (choice){
		case 1:   //改变封禁ping状态 
			change_ping(sockfd, len);
			break;
		case 2:   //改变封禁ip状态 
			change_ip(sockfd, len);
			break;
		case 3:   //改变封禁端口状态 
			change_port(sockfd, len);
			break;
		case 4:
			exit(0);
		default:
			printf("error");
	}
}

void change_ping(int sockfd, socklen_t len)
{
	//当前封禁ping状态取反 
	rules.ping_status = !rules.ping_status;
	if(setsockopt(sockfd, IPPROTO_IP, BANPING, &rules, len))
			printf("setsockopt");
}

void change_ip(int sockfd, socklen_t len)
{
	char str_ip[20];
	int choice;
	if(rules.ip_status == 0){   //若当前无封禁ip，则改变ip状态，由用户输入需封禁ip 
		rules.ip_status = 1;
		printf("enter one ip:");
		getchar();
		gets(str_ip);
		rules.ban_ip = inet_addr(str_ip); //转换ip格式 
		if (setsockopt(sockfd, IPPROTO_IP, BANIP, &rules, len))
			printf("setsockopt");
	}else{                     //若当前已有封禁ip，则取消封禁 
		rules.ip_status = 0;
		rules.ban_ip = 0;
		if(setsockopt(sockfd, IPPROTO_IP, BANIP, &rules, len))
			printf("setsockopt");
	}
}

void change_port(int sockfd, socklen_t len)
{
	if(rules.port_status == 0)   //若当前无封禁端口，则改变端口状态，由用户输入需封禁端口 
	{
		rules.port_status = 1;
		printf("enter one port:");
		scanf("%hu", &rules.ban_port);
		if(setsockopt(sockfd, IPPROTO_IP, BANPORT, &rules, len))
			printf("setsockopt");
	}else{                       //若当前已有封禁端口，则取消封禁
		rules.port_status = 0;
		if(setsockopt(sockfd, IPPROTO_IP, BANPORT, &rules, len))
			printf("setsockopt");		
	}
}


