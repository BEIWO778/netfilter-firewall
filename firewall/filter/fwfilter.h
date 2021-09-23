#define SOE_MIN		  0x6000  //驱动程序处理最小值 
#define BANPING       0x6001  //过滤程序和驱动程序对话时禁ping功能编号 
#define BANIP         0x6002  //禁ip功能编号 
#define BANPORT       0x6003  //禁port功能编号 
#define NOWRULE       0x6004  //获取防火墙当前规则功能编号 
#define SOE_MAX		  0x6100  //驱动程序处理最大值 

typedef struct ban_status{
	int ping_status;            //是否禁ping，1禁止，0未设置 
	int ip_status;              //是否禁ip，1禁止，0未设置 
	int port_status;            //是否禁port，1禁止，0未设置 
	unsigned int ban_ip;        //禁ip数值 
	unsigned short ban_port;    //禁port数值
}ban_status;
