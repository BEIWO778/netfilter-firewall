#define SOE_MIN		  0x6000  //������������Сֵ 
#define BANPING       0x6001  //���˳������������Ի�ʱ��ping���ܱ�� 
#define BANIP         0x6002  //��ip���ܱ�� 
#define BANPORT       0x6003  //��port���ܱ�� 
#define NOWRULE       0x6004  //��ȡ����ǽ��ǰ�����ܱ�� 
#define SOE_MAX		  0x6100  //�������������ֵ 

typedef struct ban_status{
	int ping_status;            //�Ƿ��ping��1��ֹ��0δ���� 
	int ip_status;              //�Ƿ��ip��1��ֹ��0δ���� 
	int port_status;            //�Ƿ��port��1��ֹ��0δ���� 
	unsigned int ban_ip;        //��ip��ֵ 
	unsigned short ban_port;    //��port��ֵ
}ban_status;
