#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <net/tcp.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include "fwfilter.h"

//和数据包处理有关钩子 
static struct nf_hook_ops nfhoLocalIn;
static struct nf_hook_ops nfhoLocalOut;
static struct nf_hook_ops nfhoPreRouting;
static struct nf_hook_ops nfhoForwarding;
static struct nf_hook_ops nfhoPostRouting;

//处理应用通信钩子 
static struct nf_sockopt_ops nfhoSockopt;

ban_status rules, recv;
 
unsigned int hookLocalIn(void* priv, struct sk_buff* skb, const struct nf_hook_state* state)
{
	struct iphdr *iph = ip_hdr(skb);
	struct tcphdr *tcph = NULL;
	struct udphdr *udph = NULL;
	unsigned short port = ntohs(rules.ban_port);
	
	//ban ping
	//如果数据包是icmp并且rules.ping_status为1则丢弃数据包 
	if(iph->protocol == IPPROTO_ICMP && rules.ping_status == 1){
		return NF_DROP;
	}
	
	//ban port
	//rules.port_status为1并且源端口符合，丢弃该端口udp或tcp的数据包 
	if(rules.port_status == 1){
		switch(iph->protocol){          //选择协议类型 
			case IPPROTO_TCP:
				tcph = tcp_hdr(skb);    //获得tcp头 
				if(tcph->dest == port){
					return NF_DROP;
					break;
				}
			case IPPROTO_UDP:
				udph = udp_hdr(skb);    //获得udp头 
				if(udph->dest == port){
					return NF_DROP;
					break;
				}
		}
	}

	//ban ip
	//rules.ip_status为1并且源ip地址符合，丢弃该源ip发送的数据包 
	if (rules.ip_status == 1){
		if (rules.ban_ip == iph->saddr){  
			return NF_DROP;
		}
	}
	//以上情况都不符合接收数据包 
	return NF_ACCEPT;
}
//其他函数接收数据包并打印信息 
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
	//从用户空间复制数据 
	ret = copy_from_user(&recv, user, sizeof(recv));
	//命令类型 
	switch(cmd){
		case BANPING:  //禁止ping 
			rules.ping_status = recv.ping_status;
			break;
		case BANIP:    //禁止ip 
			rules.ip_status = recv.ip_status;
			rules.ban_ip = recv.ban_ip;
			break;
		case BANPORT:  //禁止端口 
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
	//将数据从内核复制到用户空间 
	ret = copy_to_user(user, &rules, sizeof(rules));
	if (ret != 0)
	{
		ret = -EINVAL;
		printk("copy_to_user error");
	}

	return ret;
}
//初始化模块 
int init_module()
{
	rules.ping_status = 0;   //初始化ping状态，设置为0不封禁 
	rules.ip_status = 0;     //初始化ip状态，设置为0不封禁 
	rules.port_status = 0;   //初始化端口状态，设置为0不封禁 

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
	nfhoSockopt.set_optmin = SOE_MIN;  //指定最小值 
	nfhoSockopt.set_optmax = SOE_MAX;  //指定最大值 
	nfhoSockopt.set = hookSockoptSet;
	nfhoSockopt.get_optmin = SOE_MIN;
	nfhoSockopt.get_optmax = SOE_MAX;
	nfhoSockopt.get = hookSockoptGet;

	nf_register_sockopt(&nfhoSockopt);

	printk("My nf register\n");

	return 0;
}

//清理模块 
void cleanup_module()
{
	//注销钩子 
	nf_unregister_net_hook(&init_net, &nfhoLocalIn);
	nf_unregister_net_hook(&init_net, &nfhoLocalOut);
	nf_unregister_net_hook(&init_net, &nfhoPreRouting);
	nf_unregister_net_hook(&init_net, &nfhoForwarding);
	nf_unregister_net_hook(&init_net, &nfhoPostRouting);
	//注销扩展套接字 
	nf_unregister_sockopt(&nfhoSockopt);

	printk("My nf unregister\n");
}

MODULE_LICENSE("GPL");


