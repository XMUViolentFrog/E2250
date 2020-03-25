#define _CRT_SECURE_NO_WARNINGS
#define HAVE_REMOTE
#define WIN32  
#define FROM_NIC
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
FILE* msg;
FILE* fp;
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

void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);//回调函数

unordered_map<string,int> srcstatistics;
unordered_map<string, int> dststatistics;
time_t originTime;
time_t currentTime;
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
	char packet_filter[] = "ip and udp";
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

	time(&originTime);
	pcap_loop(adhandle, 0, packet_handler, NULL);
	fclose(fp);
#else
	char source[PCAP_BUF_SIZE];
	char testFile[] = "test.pcap";
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
	time(&originTime);
	pcap_loop(fp, 0, packet_handler, NULL);


#endif // FROM_NIC
}

void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data)
{
	struct tm ltime;
	mac_header* mh;
	ip_header* ih;
	int length = sizeof(mac_header) + sizeof(ip_header);
	char timestr[25];
	time_t local_tv_sec;
	local_tv_sec = header->ts.tv_sec;
	localtime_s(&ltime, &local_tv_sec);
	int size = header->len;
	if (size > 1048576)
	{
		printf("WARNING THE SIZE IS %d\n", size);
	}
	strftime(timestr, sizeof timestr, "%Y-%m-%d %H:%M:%S", &ltime);

	/*print time*/
	//printf("%s", timestr);

	mh = (mac_header*)pkt_data;
	ih = (ip_header*)(pkt_data + sizeof(mac_header));

	/*u_char* message = (u_char*)(pkt_data + sizeof(mac_header) + sizeof(ip_header));
	for (int i = 0; i < size; i++)
	{
		fprintf(msg, "%c ", message[i]);
	}
	fprintf(msg, "\n");*/


	/*print srcmac*/
	char srcmac[100];

	sprintf(srcmac, "%02x-%02x-%02x-%02x-%02x-%02x", mh->src_addr[0], mh->src_addr[1], mh->src_addr[2], mh->src_addr[3], mh->src_addr[4], mh->src_addr[5]);
	
	/*print srcIP*/
	char srcip[100];
	sprintf(srcip, "%d.%d.%d.%d", ih->saddr[0], ih->saddr[1], ih->saddr[2], ih->saddr[3]);

	/*print dstmac*/
	char dstmac[100];

	sprintf(dstmac, "%02x-%02x-%02x-%02x-%02x-%02x", mh->dest_addr[0], mh->dest_addr[1], mh->dest_addr[2], mh->dest_addr[3], mh->dest_addr[4], mh->dest_addr[5]);


	char dstip[100];
	sprintf(dstip, "%d.%d.%d.%d", ih->daddr[0], ih->daddr[1], ih->daddr[2], ih->daddr[3]);
	char outstring[200];
	sprintf(outstring, "%s,%s,%s,%s,%s\n", timestr, srcmac, srcip, dstmac, dstip);
	cout << outstring;
	fputs(outstring, fp);

	string mac = srcmac;
	string ip = srcip;
	string ret = mac + ip;

	string dmc = dstmac;
	string dip = dstip;
	string dret = dmc + dip;


	time_t currentTime;
	time(&currentTime);
	if (srcstatistics.find(ret) == srcstatistics.end())
	{
		srcstatistics.insert(make_pair(ret, size));
	}
	else
	{
		auto it = srcstatistics.find(ret);
		it->second += size;
	}

	if (dststatistics.find(dret) == dststatistics.end())
	{
		dststatistics.insert(make_pair(dret, size));
	}
	else
	{

		auto it = dststatistics.find(dret);
		it->second += size;
	}

	
	if (currentTime - originTime >= 60)
	{
		cout << "show SRCstatistics----------------------------------------------------" << endl;
		auto it = srcstatistics.begin();
		while (it!= srcstatistics.end())
		{
			cout << it->first << " " << it->second << endl;
			++it;
		}
		cout << "end SRCstatistics------------------------------------------------------" << endl;

		cout << "show DSTstatistics----------------------------------------------------" << endl;
		it = dststatistics.begin();
		while (it != dststatistics.end())
		{
			cout << it->first << " " << it->second << endl;
			++it;
		}
		dststatistics.clear();

		cout << "end DSTstatistics------------------------------------------------------" << endl;

		originTime = currentTime;
	}
	
}
