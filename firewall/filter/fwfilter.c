#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <net/tcp.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include "fwfilter.h"

//�����ݰ������йع��� 
static struct nf_hook_ops nfhoLocalIn;
static struct nf_hook_ops nfhoLocalOut;
static struct nf_hook_ops nfhoPreRouting;
static struct nf_hook_ops nfhoForwarding;
static struct nf_hook_ops nfhoPostRouting;

//����Ӧ��ͨ�Ź��� 
static struct nf_sockopt_ops nfhoSockopt;

ban_status rules, recv;
 
unsigned int hookLocalIn(void* priv, struct sk_buff* skb, const struct nf_hook_state* state)
{
	struct iphdr *iph = ip_hdr(skb);
	struct tcphdr *tcph = NULL;
	struct udphdr *udph = NULL;
	unsigned short port = ntohs(rules.ban_port);
	
	//ban ping
	//������ݰ���icmp����rules.ping_statusΪ1�������ݰ� 
	if(iph->protocol == IPPROTO_ICMP && rules.ping_status == 1){
		return NF_DROP;
	}
	
	//ban port
	//rules.port_statusΪ1����Դ�˿ڷ��ϣ������ö˿�udp��tcp�����ݰ� 
	if(rules.port_status == 1){
		switch(iph->protocol){          //ѡ��Э������ 
			case IPPROTO_TCP:
				tcph = tcp_hdr(skb);    //���tcpͷ 
				if(tcph->dest == port){
					return NF_DROP;
					break;
				}
			case IPPROTO_UDP:
				udph = udp_hdr(skb);    //���udpͷ 
				if(udph->dest == port){
					return NF_DROP;
					break;
				}
		}
	}

	//ban ip
	//rules.ip_statusΪ1����Դip��ַ���ϣ�������Դip���͵����ݰ� 
	if (rules.ip_status == 1){
		if (rules.ban_ip == iph->saddr){  
			return NF_DROP;
		}
	}
	//��������������Ͻ������ݰ� 
	return NF_ACCEPT;
}
//���������������ݰ�����ӡ��Ϣ 
unsigned int hookLocalOut(void* priv, struct sk_buff* skb, const struct nf_hook_state* state)
{
	printk("hookLocalOut");
	return NF_ACCEPT;
}
unsigned int hookPreRouting(void* priv, struct sk_buff* skb, const struct nf_hook_state* state)
{
	printk("hookPreRouting");
	return NF_ACCEPT;
}
unsigned int hookPostRouting(void* priv, struct sk_buff* skb, const struct nf_hook_state* state)
{
	printk("hookPostRouting");
	return NF_ACCEPT;
}
unsigned int hookForwarding(void* priv, struct sk_buff* skb, const struct nf_hook_state* state)
{
	printk("hookForwarding");
	return NF_ACCEPT;
}

int hookSockoptSet(struct sock* sock, int cmd, void __user* user, unsigned int len)
{
	int ret;
	printk("hookSockoptSet");
	//���û��ռ临������ 
	ret = copy_from_user(&recv, user, sizeof(recv));
	//�������� 
	switch(cmd){
		case BANPING:  //��ֹping 
			rules.ping_status = recv.ping_status;
			break;
		case BANIP:    //��ֹip 
			rules.ip_status = recv.ip_status;
			rules.ban_ip = recv.ban_ip;
			break;
		case BANPORT:  //��ֹ�˿� 
			rules.port_status = recv.port_status;
			rules.ban_port = recv.ban_port;
			break;
		default:
			break;
	}
	if (ret != 0)
	{
		ret = -EINVAL;
		printk("copy_from_user error");
	}

	return ret;
}

int hookSockoptGet(struct sock* sock, int cmd, void __user* user, int* len)
{
	int ret;
	
	printk("hookSockoptGet");
	//�����ݴ��ں˸��Ƶ��û��ռ� 
	ret = copy_to_user(user, &rules, sizeof(rules));
	if (ret != 0)
	{
		ret = -EINVAL;
		printk("copy_to_user error");
	}

	return ret;
}
//��ʼ��ģ�� 
int init_module()
{
	rules.ping_status = 0;   //��ʼ��ping״̬������Ϊ0����� 
	rules.ip_status = 0;     //��ʼ��ip״̬������Ϊ0����� 
	rules.port_status = 0;   //��ʼ���˿�״̬������Ϊ0����� 

	nfhoLocalIn.hook = hookLocalIn;         
	nfhoLocalIn.pf = PF_INET;
	nfhoLocalIn.priority = NF_IP_PRI_FIRST;
	nf_register_net_hook(&init_net, &nfhoLocalIn);

	nfhoLocalOut.hook = hookLocalOut;
	nfhoLocalOut.pf = PF_INET;
	nfhoLocalOut.priority = NF_IP_PRI_FIRST;
	nf_register_net_hook(&init_net, &nfhoLocalOut);

	nfhoPreRouting.hook = hookPreRouting;
	nfhoPreRouting.pf = PF_INET;
	nfhoPreRouting.priority = NF_IP_PRI_FIRST;
	nf_register_net_hook(&init_net, &nfhoPreRouting);

	nfhoForwarding.hook = hookForwarding;
	nfhoForwarding.pf = PF_INET;
	nfhoForwarding.priority = NF_IP_PRI_FIRST;
	nf_register_net_hook(&init_net, &nfhoForwarding);

	nfhoPostRouting.hook = hookPostRouting;
	nfhoPostRouting.pf = PF_INET;
	nfhoPostRouting.priority = NF_IP_PRI_FIRST;
	nf_register_net_hook(&init_net, &nfhoPostRouting);

	nfhoSockopt.pf = PF_INET;
	nfhoSockopt.set_optmin = SOE_MIN;  //ָ����Сֵ 
	nfhoSockopt.set_optmax = SOE_MAX;  //ָ�����ֵ 
	nfhoSockopt.set = hookSockoptSet;
	nfhoSockopt.get_optmin = SOE_MIN;
	nfhoSockopt.get_optmax = SOE_MAX;
	nfhoSockopt.get = hookSockoptGet;

	nf_register_sockopt(&nfhoSockopt);

	printk("My nf register\n");

	return 0;
}

//����ģ�� 
void cleanup_module()
{
	//ע������ 
	nf_unregister_net_hook(&init_net, &nfhoLocalIn);
	nf_unregister_net_hook(&init_net, &nfhoLocalOut);
	nf_unregister_net_hook(&init_net, &nfhoPreRouting);
	nf_unregister_net_hook(&init_net, &nfhoForwarding);
	nf_unregister_net_hook(&init_net, &nfhoPostRouting);
	//ע����չ�׽��� 
	nf_unregister_sockopt(&nfhoSockopt);

	printk("My nf unregister\n");
}

MODULE_LICENSE("GPL");


