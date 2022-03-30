#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <time.h>
#include <arpa/inet.h>
#include <cstring>
#include <iostream>
#include <string>

#define BUFSIZE 10240
#define STRSIZE 1024
#define FILE_NAME "git_push.pcap"

typedef u_int32_t u_int32;
typedef u_int16_t u_int16;
typedef u_int8_t u_int8;
 
//pacp文件头结构体
/*
Pcap文件头24B各字段说明：
Magic：4B：0x1A 2B 3C 4D:用来标示文件的开始
Major：2B，0x02 00:当前文件主要的版本号     
Minor：2B，0x04 00当前文件次要的版本号
ThisZone：4B当地的标准时间；全零
SigFigs：4B时间戳的精度；全零
SnapLen：4B最大的存储长度    
LinkType：4B链路类型
常用类型：
0            BSD loopback devices, except for later OpenBSD
1            Ethernet, and Linux loopback devices
6            802.5 Token Ring
7            ARCnet
8            SLIP
9            PPP
*/
typedef struct pcap_file_header
{
    u_int32 Magic;       /* 0xa1b2c3d4 */
    u_short VersionMajor;   /* magjor Version 2 */
    u_short VersionMinor;   /* magjor Version 4 */
    u_int32 ThisZone;      /* gmt to local correction */
    u_int32 Sigfigs;     /* accuracy of timestamps */
    u_int32 SnapLen;     /* max length saved portion of each pkt */
    u_int32 LinkType;    /* data link type (LINKTYPE_*) */
}pcap_file_header;

/*
Packet包头和Packet数据组成
字段说明：
Timestamp：时间戳高位，精确到seconds     
Timestamp：时间戳低位，精确到microseconds
Caplen：当前数据区的长度，即抓取到的数据帧长度，由此可以得到下一个数据帧的位置。
Len：离线数据长度：网络中实际数据帧的长度，一般不大于caplen，多数情况下和Caplen数值相等。
Packet数据：即 Packet（通常就是链路层的数据帧）具体内容，长度就是Caplen，这个长度的后面，就是当前PCAP文件中存放的下一个Packet数据包，也就 是说：PCAP文件里面并没有规定捕获的Packet数据包之间有什么间隔字符串，下一组数据在文件中的起始位置。我们需要靠第一个Packet包确定。
*/
//时间戳
typedef struct time_val
{
    int Tv_sec;         /* seconds 含义同 time_t 对象的值 */
    int Tv_usec;        /* and microseconds */
}time_val;
 
//pcap数据包头结构体
typedef struct pcap_pkthdr
{
    time_val Ts;  /* time stamp */
    u_int32 Caplen; /* length of portion present */
    u_int32 Len;    /* length this packet (off wire) */
}pcap_pkthdr;
 
//Pcap捕获的数据帧头
typedef struct Fram_Header
{
    u_int8 DstMAC[6]; //目的MAC地址
    u_int8 SrcMAC[6]; //源MAC地址
    u_int8 FrameType[2];    //帧类型
}__attribute__((packed)) Fram_Header;
 
//IP数据报头
typedef struct IP_Header
{
    u_int8 Ver_HLen;       //版本+报头长度
    u_int8 TOS;            //服务类型
    u_int16 TotalLen;       //总长度
    u_int16 ID; //标识
    u_int16 FlagSegment;   //标志+片偏移
    u_int8 TTL;            //生存周期
    u_int8 Protocol;       //协议类型
    u_int16 Checksum;       //头部校验和
    u_int32 SrcIP; //源IP地址
    u_int32 DstIP; //目的IP地址
} IP_Header;
 
//TCP数据报头
typedef struct TCP_Header
{
    u_int16 SrcPort; //源端口
    u_int16 DstPort; //目的端口
    u_int32 SeqNO; //序号
    u_int32 AckNO; //确认号
    u_int8 HeaderLen; //数据报头的长度(4 bit) + 保留(4 bit)
    u_int8 Flags; //保留(4 bit) + 标识TCP不同的控制消息(6 bit)
    u_int16 Window; //窗口大小
    u_int16 Checksum; //校验和
    u_int16 UrgentPointer;  //紧急指针
}TCP_Header;

// UDP数据报头
typedef struct UDP_Header
{
    u_int16 SrcPort;
    u_int16 DstPort;
    u_int16 TotalLen;
    u_int16 Checksum;
}UDP_Header;

// DNS协议头
typedef struct DNS_Header 
{
	u_int16 ID;			//会话标识
	u_int16 Flags;		//标志
	u_int16 Questions;	//问题数
	u_int16 Answer;		//回答 资源记录数
	u_int16 Authority;	//授权 资源记录数
	u_int16 Additional;	//附加 资源记录数
}DNS_Header;

// struct DNA_Queries 
// {
// 	u_int32 length;
// 	u_int16 qtype;
// 	u_int16 qclass;
// 	unsigned char* name;
// }DNA_Queries;

// struct DNS_Item 
// {
// 	char* domain;
// 	char* ip;
// }DNS_Item;

// TLS头部
typedef struct TLS_Header 
{
	u_int8 Type;
	u_int16 Version;
	u_int16 Length;
}__attribute__((packed)) TLS_Header;

typedef struct TLS_1 
{
	u_int8 HandShakeTYpe;
	u_int8 Length1;
	u_int16 Length2;
    u_int16 Version;
    u_int32 Random[8];
    u_int16 SessionIDLength;
}__attribute__((packed)) TLS_1;

template <class T> T reverse_by_bit(T & a); // 按位反转数据(处理大端存储问题)
 
int main()
{
    pcap_file_header *file_header;
    pcap_pkthdr *ptk_header;
    Fram_Header *mac_header;
    IP_Header *ip_header;
    TCP_Header *tcp_header;
    UDP_Header *udp_header;
    DNS_Header *dns_header;
    TLS_Header *tls_header;
    TLS_1 *tls_1;
 
    FILE *fp, *output;
    int pkt_offset, i = 0;
    int src_port, dst_port;
    char my_time[STRSIZE], src_ip[STRSIZE], dst_ip[STRSIZE];
 
    //初始化
    file_header = (pcap_file_header *)malloc(sizeof(pcap_file_header));
    ptk_header = (pcap_pkthdr *)malloc(sizeof(pcap_pkthdr));
    mac_header = (Fram_Header *)malloc(sizeof(Fram_Header));
    ip_header = (IP_Header *)malloc(sizeof(IP_Header));
    tcp_header = (TCP_Header *)malloc(sizeof(TCP_Header));
    udp_header = (UDP_Header *)malloc(sizeof(UDP_Header));
    dns_header = (DNS_Header *)malloc(sizeof(DNS_Header));
    tls_header = (TLS_Header *)malloc(sizeof(TLS_Header));
    tls_1 = (TLS_1 *)malloc(sizeof(TLS_1));
 
    // 打开文件
    if ((fp = fopen(FILE_NAME, "r")) == NULL)
    {
        printf("Error: can not open pcap file\n");
        exit(0);
    }
    if ((output = fopen("output.txt", "w+")) == NULL)
    {
        printf("Error: can not open output file\n");
        exit(0);
    }
 
    // 开始读数据包
    pkt_offset = 24; //pcap文件头结构 24个字节

    // 打印pcap文件头信息
    fread(file_header, sizeof(pcap_file_header), 1, fp);
    if (file_header!=NULL) {
        fprintf(output, "==============Now parsing pcap file=============\n\n"
            "1. Pcap file header info\n-----------------------------------\n"
            "Magic:0x%0x\n"
            "Version_Major:%u\n"
            "Version_Minor:%u\n"
            "Thiszone:%u\n"
            "Sigfigs:%u\n"
            "Snaplen:%u\n"
            "Linktype:%u\n"
            "-----------------------------------\n",
            file_header->Magic,
            file_header->VersionMajor,
            file_header->VersionMinor,
            file_header->ThisZone,
            file_header->Sigfigs,
            file_header->SnapLen,
            file_header->LinkType);
    }

    while (fseek(fp, pkt_offset, SEEK_SET) == 0) //遍历数据包
    {
        i++;
        //pcap_pkt_header 16 byte
        memset(ptk_header, 0, sizeof(struct pcap_pkthdr));
        if (fread(ptk_header, 16, 1, fp) != 1) //读pcap数据包头结构
        {
            fprintf(output, "\nRead end of pcap file\n");
            break;
        }
 
        pkt_offset += 16 + ptk_header->Caplen;   //下一个数据包的偏移值

        //读取pcap包时间戳，转换成标准格式时间
        struct tm *timeinfo;
        time_t t = (time_t)(ptk_header->Ts.Tv_sec);
        timeinfo = localtime(&t);
        strftime(my_time, sizeof(my_time), "%Y-%m-%u %H:%M:%S", timeinfo); //获取时间

        if (ptk_header!=NULL) {
            fprintf(output, "\n====================================================================================\n"
                "The packet sequence in pcap file is %u.\n-----------------------------------\n"
                "2. Packet file header info\n-----------------------------------\n"
                "Timestamp_s:%u\n"
                "Timestamp_ms:%u\n"
                "Time in real world:%s\n"
                "Capture_length:%u\n"
                "Length:%u\n"
                "-----------------------------------\n",
                i,
                ptk_header->Ts.Tv_sec,
                ptk_header->Ts.Tv_usec,
                my_time,
                ptk_header->Caplen,
                ptk_header->Len);
        }
 
        //数据帧头 14字节
        fread(mac_header, 14, 1, fp);
        if (mac_header!=NULL) {
            fprintf(output, "3. MAC header info\n-----------------------------------\nMAC destination address:");
            for (auto iter_MAC : mac_header->DstMAC){
                if (iter_MAC == mac_header->DstMAC[0]){
                    fprintf(output, "%02x", iter_MAC);
                    continue;
                }
                fprintf(output, ":%02x", iter_MAC);
            }
            fprintf(output, "\nMAC source address:");
            for (auto iter_MAC : mac_header->SrcMAC){
                if (iter_MAC == mac_header->SrcMAC[0]){
                    fprintf(output, "%02x", iter_MAC);
                    continue;
                }
                fprintf(output, ":%02x", iter_MAC);
            }
            fprintf(output, "\nFrame type:0x%02x%02x\n"
                "-----------------------------------\n",
                mac_header->FrameType[0],
                mac_header->FrameType[1]);
        }

        //IP数据报头 20字节
        memset(ip_header, 0, sizeof(IP_Header));
        if (fread(ip_header, sizeof(IP_Header), 1, fp) != 1)
        {
            fprintf(output, "%u: Can not read ip_header\n", i);
            break;
        }
 
        inet_ntop(AF_INET, (void *)&(ip_header->SrcIP), src_ip, 16);
        inet_ntop(AF_INET, (void *)&(ip_header->DstIP), dst_ip, 16);

        fprintf(output, "4. IP protocol header info\n-----------------------------------\n"
                "Version:%u\n"
                "IP header length:%u bytes\n"
                "Total length:%u bytes\n"
                "Flag segment:%u\n"
                "TTL:%u\n"
                "Protocol:%u\n"
                "IP source address:%s\n"
                "IP destination address:%s\n"
                "Flags meanings:",
                (ip_header->Ver_HLen & 0xf0) / 16,
                (ip_header->Ver_HLen & 0x0f) * 4,
                ip_header->TotalLen / 256,
                ip_header->FlagSegment,
                ip_header->TTL,
                ip_header->Protocol,
                src_ip,
                dst_ip);
        
        if ((ip_header->FlagSegment & 0x80) == 128){
            fprintf(output, "reserved bit,");
        }
        if ((ip_header->FlagSegment & 0x40) == 64){
            fprintf(output, "don't fragment");
        }
        if ((ip_header->FlagSegment & 0x20) == 32){
            fprintf(output, "more fragments");
        }
        fprintf(output, "\n-----------------------------------\n");

        //TCP头 20字节
        if (ip_header->Protocol == 6){
            fread(tcp_header, sizeof(TCP_Header), 1, fp);
            src_port = ntohs(tcp_header->SrcPort);
            dst_port = ntohs(tcp_header->DstPort);
            
            fprintf(output, "5. TCP protocol header info\n-----------------------------------\n"
                "TCP source port:%u\n"
                "TCP destination port:%u\n"
                "Sequence number:%u\n"
                "Acknowledge number:%u\n"
                "TCP header length:%u bytes\n"
                "Flags:%u\n"
                "Ack:%u\n"
                "Syn:%u\n"
                "Fin:%u\n"
                "Window size:%u\n"
                "-----------------------------------\n",
                src_port,
                dst_port,
                tcp_header->SeqNO,
                tcp_header->AckNO,
                (tcp_header->HeaderLen >> 4) * 4,
                tcp_header->Flags,
                (tcp_header->Flags & 0x10) >> 4,
                (tcp_header->Flags & 0x02) >> 1,
                (tcp_header->Flags & 0x01),
                tcp_header->Window);
            
            // TLS协议
            if (ptk_header->Caplen > 60){
                fprintf(output, "6. TLS protocol\n-----------------------------------\n");
                fread(tls_header, sizeof(TLS_Header), 1, fp);
                if (tls_header->Type == 22){
                    fread(tls_1, sizeof(TLS_1), 1, fp);
                    char *CipherSuitesLength=(char *)malloc(2);
                    u_int16 *CipherSuites=(u_int16 *)malloc(2);
                    if (tls_1->HandShakeTYpe == 1){
                        fprintf(output, "Client Hello\nCipherSuites:\n");
                        int count=0;
                        fread(CipherSuitesLength, 2, 1, fp);
                        while(count < *CipherSuitesLength / 2){
                            count++;
                            fread(CipherSuites, 2, 1, fp);
                            fprintf(output, "\t%u:0x%04x\n", count, *CipherSuites);
                        }
                    }
                    if (tls_1->HandShakeTYpe == 2){
                        fprintf(output, "Server Hello\nCipherSuite:\n");
                        fread(CipherSuites, 2, 1, fp);
                        fprintf(output, "\t0x%04x\n", *CipherSuites);
                    }
                }
                else if (tls_header->Type == 20){
                    fprintf(output, "Change Cipher Spec\n-----------------------------------\n");
                }
                else fprintf(output, "Application Data\n-----------------------------------\n");
            }

        }
        
        // UDP头 8字节
        if (ip_header->Protocol == 17){
            fread(udp_header, sizeof(UDP_Header), 1, fp);
            src_port = ntohs(udp_header->SrcPort);
            dst_port = ntohs(udp_header->DstPort);
            fprintf(output, "5. UDP protocol header info\n-----------------------------------\n"
                "UDP source port:%u\n"
                "UDP destination port:%u\n"
                "Total length:%u\n"
                "-----------------------------------\n",
                src_port,
                dst_port,
                udp_header->TotalLen);
            
            // DNS协议
            if ((src_port == 53) || (dst_port == 53)){
                fprintf(output, "6. DNS protocol\n-----------------------------------\n");
                fread(dns_header, sizeof(DNS_Header), 1, fp);
                char *netname = (char *)malloc(11);
                fseek(fp, 1, SEEK_CUR);
                fread(netname, 11, 1, fp);
                std::string netname1 = netname;
                netname1.replace(6,1,".");
                fprintf(output, "Query name:%s\n", netname1.c_str());
                if (dns_header->Answer){
                    fseek(fp, 16, SEEK_CUR);
                    fread(dst_ip, 4, 1, fp);
                    inet_ntop(AF_INET, (void *)&dst_ip, dst_ip, 16);
                    fprintf(output, "Answered IP address:%s\n", dst_ip);
                }
                fprintf(output, "-----------------------------------\n");
            }
        }
    } // end while
    printf("Finish");
    fclose(fp);
    fclose(output);
    free(file_header);
    free(ptk_header);
    free(ip_header);
    free(tcp_header);
    return 0;
}

// 按位反转数据(处理大端存储问题)
template <class T> T reverse_by_bit(T &a){
    if (sizeof(a) == 1){
        a = (((a & 0xaa) >> 1) | ((a & 0x55) << 1));
        a = (((a & 0xcc) >> 2) | ((a & 0x33) << 2));
        return ((a >> 4) | (a << 4));
    }
    else if (sizeof(a) == 2){
        a = (((a & 0xaaaa) >> 1) | ((a & 0x5555) << 1));
        a = (((a & 0xcccc) >> 2) | ((a & 0x3333) << 2));
        a = (((a & 0xf0f0) >> 4) | ((a & 0x0f0f) << 4));
        return ((a >> 8) | (a << 8));
    }
    else if (sizeof(a) == 4){
        a = (((a & 0xaaaaaaaa) >> 1) | ((a & 0x55555555) << 1));
        a = (((a & 0xcccccccc) >> 2) | ((a & 0x33333333) << 2));
        a = (((a & 0xf0f0f0f0) >> 4) | ((a & 0x0f0f0f0f) << 4));
        a = (((a & 0xff00ff00) >> 8) | ((a & 0x00ff00ff) << 8));
        return ((a >> 16) | (a << 16));
    }
    return a;
}