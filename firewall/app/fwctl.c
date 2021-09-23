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
void get_status();                              //��õ�ǰ����ǽ������        
void change_status(int sockfd, socklen_t len);  //�ı����ǽ������ 
void change_ping(int sockfd, socklen_t len);    //�ı�ping������ 
void change_ip(int sockfd, socklen_t len);      //�ı�ip������ 
void change_port(int sockfd, socklen_t len);    //�ı�˿ڹ����� 

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
			//��ӡ��ǰ����ǽ����͸ı����˵� 
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
	//rules.ping_statusΪ1ʱ��ֹping 
	if(rules.ping_status == 1)
		printf("ban ping\n");
	else
		printf("no ban ping\n");
	//��ӡ��ǰ��ֹipֵ 
	if(rules.ip_status == 1){
		printf("ban ip:%d.%d.%d.%d\n", 
			(rules.ban_ip & 0x000000ff) >> 0,
			(rules.ban_ip & 0x0000ff00) >> 8,
			(rules.ban_ip & 0x00ff0000) >> 16,
			(rules.ban_ip & 0xff000000) >> 24);
	}else{
		printf("no ban ip\n");
	}
	//��ӡ��ǰ��ֹipֵ 
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
		case 1:   //�ı���ping״̬ 
			change_ping(sockfd, len);
			break;
		case 2:   //�ı���ip״̬ 
			change_ip(sockfd, len);
			break;
		case 3:   //�ı����˿�״̬ 
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
	//��ǰ���ping״̬ȡ�� 
	rules.ping_status = !rules.ping_status;
	if(setsockopt(sockfd, IPPROTO_IP, BANPING, &rules, len))
			printf("setsockopt");
}

void change_ip(int sockfd, socklen_t len)
{
	char str_ip[20];
	int choice;
	if(rules.ip_status == 0){   //����ǰ�޷��ip����ı�ip״̬�����û���������ip 
		rules.ip_status = 1;
		printf("enter one ip:");
		getchar();
		gets(str_ip);
		rules.ban_ip = inet_addr(str_ip); //ת��ip��ʽ 
		if (setsockopt(sockfd, IPPROTO_IP, BANIP, &rules, len))
			printf("setsockopt");
	}else{                     //����ǰ���з��ip����ȡ����� 
		rules.ip_status = 0;
		rules.ban_ip = 0;
		if(setsockopt(sockfd, IPPROTO_IP, BANIP, &rules, len))
			printf("setsockopt");
	}
}

void change_port(int sockfd, socklen_t len)
{
	if(rules.port_status == 0)   //����ǰ�޷���˿ڣ���ı�˿�״̬�����û����������˿� 
	{
		rules.port_status = 1;
		printf("enter one port:");
		scanf("%hu", &rules.ban_port);
		if(setsockopt(sockfd, IPPROTO_IP, BANPORT, &rules, len))
			printf("setsockopt");
	}else{                       //����ǰ���з���˿ڣ���ȡ�����
		rules.port_status = 0;
		if(setsockopt(sockfd, IPPROTO_IP, BANPORT, &rules, len))
			printf("setsockopt");		
	}
}


