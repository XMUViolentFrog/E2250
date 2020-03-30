#define _CRT_SECURE_NO_WARNINGS
#define HAVE_REMOTE
#define WIN32  
//#define FROM_NIC
#ifdef __cplusplus /* 如果采用了C++，如下代码使用C编译器 */
extern "C" { /* 如果没有采用C++，顺序预编译 */
#endif
/* 采用C编译器编译的C语言代码段 */
#ifdef __cplusplus /* 结束使用C编译器 */
}
#endif
#include<unordered_map>
#include <pcap.h>
#include<iostream>
#include<time.h>
#include <Packet32.h>
#include <ntddndis.h>
#pragma comment(lib, "Packet")
#pragma comment(lib, "wpcap")
#pragma comment(lib, "WS2_32")
using namespace std;
FILE* fp;
void Rev16InByte(void* val)
{
	unsigned short v = *((unsigned short*)val);
	v = ((v & 0x00FF) << 8) | ((v & 0xFF00) >> 8);
	*((unsigned short*)val) = v;
};
typedef struct ip_header {
	u_char ver_ihl; // Version (4 bits) +Internet header length(4 bits)
	u_char tos; // Type of service
	u_short tlen; // Total length
	u_short identification; // Identification
	u_short flags_fo; // Flags (3 bits) + Fragmentoffset(13 bits)
	u_char ttl; // Time to live 生存空间
	u_char proto; // Protocol
	u_short crc; // Header checksum
	u_char saddr[4]; // Source address//32位源ip
	u_char daddr[4]; // Destination address//32位目的ip
	u_int op_pad; // Option + Padding
} ip_header;//IP帧格式

typedef struct mac_header {
	u_char dest_addr[6];
	u_char src_addr[6];
	u_char type[2];
} mac_header;//以太网帧格式 前同步码7字节 SFD一字节 目的地址6字节 源地址6字节 类型2字节

struct tcp_header {
	u_short srcport;//16位源端口号
	u_short dstport;//16位目的端口号
	int senumber;//段序号 32
	int acknumber;//确认号 32
	u_short foo;//4bit 头部 12
	u_short wsize;//window size 16
	u_short checksum; //16
	u_short urpoint;//urgent pointer 16
	int pad;
};

struct ftp_data
{
	string dstip;
	string User;
	string pas;
	string sta;
};

void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);//回调函数
bool is_tcp(ip_header* ih, int& ihsize, u_short& ih_totallen);

bool turn =0;
ftp_data fd;
int main()
{
	pcap_if_t* alldevs;
	pcap_if_t* d;
	pcap_t* adhandle;

	fp = fopen("out.csv", "w");
	//msg = fopen("msg.txt", "w");
	char errbuf[PCAP_ERRBUF_SIZE];
	int i = 0;
	int inum;
	u_int netmask;
	char packet_filter[] = "tcp src port ftp or tcp dst port ftp";//"tcp dst port ftp";
	struct bpf_program fcode;
#ifdef FROM_NIC

	/*获取本地适配器信息，打开适配器*/
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs,
		errbuf) == -1) {
		fprintf(stderr, "Error in pcap_findalldevs: %s\n",
			errbuf);
		exit(1);
	}
	/*打印设备*/
	for (d = alldevs; d != NULL; d = d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}
	if (i == 0) {
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}

	printf("Enter the interface number (1-%d):", i);
	scanf_s("%d", &inum);
	if (inum < 1 || inum > i)
	{
		printf("\nInterface number out of range.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/*转到选择的适配器*/
	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

	if ((adhandle = pcap_open(d->name,	// name of the device
		65536,		// portion of the packet to capture. 
				   // 65536 grants that the whole packet will be captured on all the MACs.
		PCAP_OPENFLAG_PROMISCUOUS,			// promiscuous mode
		1000,		// read timeout
		NULL,		// remote authentication
		errbuf		// error buffer
	)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	if (pcap_datalink(adhandle) != DLT_EN10MB)
	{
		fprintf(stderr, "\nThis program works only on Ethernet networks.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	if (d->addresses != NULL)
		/* Retrieve the mask of the first address of the interface */
		netmask = ((struct sockaddr_in*)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		/* If the interface is without addresses we suppose to be in a C class network */
		netmask = 0xffffff;

	if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) < 0)
	{
		fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	//set the filter
	if (pcap_setfilter(adhandle, &fcode) < 0)
	{
		fprintf(stderr, "\nError setting the filter.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	printf("\nlistening on %s...\n", d->description);


	/* At this point, we don't need any more the device list. Free it */
	pcap_freealldevs(alldevs);

	pcap_loop(adhandle, 0, packet_handler, NULL);
	fclose(fp);
#else
	char source[PCAP_BUF_SIZE];
	char testFile[] = "naive.pcap";
	if (pcap_createsrcstr(source,			// variable that will keep the source string
		PCAP_SRC_FILE,	// we want to open a file
		NULL,			// remote host
		NULL,			// port on the remote host
		testFile,		// name of the file we want to open
		errbuf			// error buffer
	) != 0)
	{
		fprintf(stderr, "\nError creating a source string\n");
		return -1;
	}
	pcap_t* fp;
	/* Open the capture file */
	if ((fp = pcap_open(source,			// name of the device
		65536,			// portion of the packet to capture
						// 65536 guarantees that the whole packet will be captured on all the link layers
		PCAP_OPENFLAG_PROMISCUOUS, 	// promiscuous mode
		1000,				// read timeout
		NULL,				// authentication on the remote machine
		errbuf			// error buffer
	)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the file %s.\n", source);
		return -1;
	}

	// read and dispatch packets until EOF is reached
	pcap_loop(fp, 0, packet_handler, NULL);


#endif // FROM_NIC
}

void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data)
{
	struct tm ltime;
	mac_header* mh;
	ip_header* ih;
	tcp_header* th;

	int totallen = header->len;

	time_t local_tv_sec;
	local_tv_sec = header->ts.tv_sec;
	localtime_s(&ltime, &local_tv_sec);
	int length = sizeof(mac_header) + sizeof(ip_header);

	/*print time*/

	mh = (mac_header*)pkt_data;
	ih = (ip_header*)(pkt_data + sizeof(mac_header));
	int ihsize = 0;
	u_short ih_totallen = ih->tlen;

	char srcip[100];
	char dstip[100];
	
	sprintf(dstip, "%d.%d.%d.%d", ih->saddr[0], ih->saddr[1], ih->saddr[2], ih->saddr[3]);

	sprintf(srcip, "%d.%d.%d.%d", ih->daddr[0], ih->daddr[1], ih->daddr[2], ih->daddr[3]);
	//cout << dstip <<" "<<srcip<< endl;

	/*判断是否存在tcp协议*/
	if (is_tcp(ih,ihsize,ih_totallen))
	{
		int tcpsize = ih_totallen - ihsize;
		th = (tcp_header*)(pkt_data + sizeof(mac_header) + ihsize);//tcp帧
		int thsize = 0;
		int t = th->foo;
		thsize = ((t & 0XF0) >> 4) * 4;

		int other_message_len;
		other_message_len = tcpsize - thsize;
		/*除头文件以外tcp长度*/
		if (other_message_len != 0)
		{
			/*ftp数据*/
			u_char* ftp = (u_char*)(pkt_data + sizeof(mac_header) + ihsize + thsize);
			string str;
			for (int i = 0; i < other_message_len; i++)
			{
				str.push_back(ftp[i]);
			}
			if (str[0] == 'U')
			{
				fd.User = str.substr(5);
			}
			if (str[0] == 'P')
			{
				fd.pas = str.substr(5);
			}
			if (str[0] == '2'&&str[1] == '3'&&str[2]=='0')//230 succe
			{
				fd.dstip = dstip;
				fd.sta = "OK";
				turn = 1;
			}
			else if (str[0] == '5' && str[1] == '3'&&str[2]=='0')
			{
				fd.dstip = dstip;
				fd.sta = "FAILED";
				turn = 1;
			}

			if (turn == 1)
			{
	//			
				string out;
				out = "FTP: " + fd.dstip + " USER:" + fd.User + "     " + "PAS:" + fd.pas + "     " + "STA:" + fd.sta;
				cout << out << endl;
				fputs(out.data(), fp);
				turn = 0;
			}


		}
	}
}
bool is_tcp(ip_header* ih,int &ihsize,u_short & ih_totallen)
{

	int x = ih->ver_ihl;
	ihsize = (x & 0xf);
	ih_totallen = ih->tlen;
	Rev16InByte(&ih_totallen);
	ihsize *= 4;
	int tcpsize = ih_totallen - ihsize;
	if (tcpsize >= 20)
	{
		return true;
	}
	else
	{
		return false;
	}
}