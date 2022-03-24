#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <time.h>
#include <arpa/inet.h>
#include <cstring>

#define BUFSIZE 10240
#define STRSIZE 1024
#define FILE_NAME "base.pcap"

typedef int32_t bpf_int32;
typedef u_int32_t bpf_u_int32;
typedef u_int16_t u_short;
typedef u_int32_t u_int32;
typedef u_int16_t u_int16;
typedef u_int8_t u_int8;

// pacp文件头结构体
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
    bpf_u_int32 magic;     /* 0xa1b2c3d4 */
    u_short version_major; /* magjor Version 2 */
    u_short version_minor; /* magjor Version 4 */
    bpf_int32 thiszone;    /* gmt to local correction */
    bpf_u_int32 sigfigs;   /* accuracy of timestamps */
    bpf_u_int32 snaplen;   /* max length saved portion of each pkt */
    bpf_u_int32 linktype;  /* data link type (LINKTYPE_*) */
} pcap_file_header;

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
    int tv_sec;  /* seconds 含义同 time_t 对象的值 */
    int tv_usec; /* and microseconds */
} time_val;

// pcap数据包头结构体
typedef struct pcap_pkthdr
{
    time_val ts;        /* time stamp */
    bpf_u_int32 caplen; /* length of portion present */
    bpf_u_int32 len;    /* length this packet (off wire) */
} pcap_pkthdr;

// Pcap捕获的数据帧头
typedef struct FramHeader_t
{
    u_int8 DstMAC[6];  //目的MAC地址
    u_int8 SrcMAC[6];  //源MAC地址
    u_short FrameType; //帧类型
} FramHeader_t;

// IP数据报头
typedef struct IPHeader_t
{
    u_int8 Ver_HLen;      //版本+报头长度
    u_int8 TOS;           //服务类型
    u_int16 TotalLen;     //总长度
    u_int16 ID;           //标识
    u_int16 Flag_Segment; //标志+片偏移
    u_int8 TTL;           //生存周期
    u_int8 Protocol;      //协议类型
    u_int16 Checksum;     //头部校验和
    u_int32 SrcIP;        //源IP地址
    u_int32 DstIP;        //目的IP地址
} IPHeader_t;

// TCP数据报头
typedef struct TCPHeader_t
{
    u_int16 SrcPort;       //源端口
    u_int16 DstPort;       //目的端口
    u_int32 SeqNO;         //序号
    u_int32 AckNO;         //确认号
    u_int8 HeaderLen;      //数据报头的长度(4 bit) + 保留(4 bit)
    u_int8 Flags;          //标识TCP不同的控制消息
    u_int16 Window;        //窗口大小
    u_int16 Checksum;      //校验和
    u_int16 UrgentPointer; //紧急指针
} TCPHeader_t;

// UDP数据报头
typedef struct udp_hdr
{
    u_short sport;
    u_short dport;
    u_short tot_len;
    u_short check_sum;
} udp_hdr;

void match_http(FILE *fp, char *head_str, char *tail_str, char *buf, int total_len); //查找 http 信息函数

int main()
{
    pcap_file_header *file_header;
    pcap_pkthdr *ptk_header;
    FramHeader_t *mac_header;
    IPHeader_t *ip_header;
    TCPHeader_t *tcp_header;

    FILE *fp, *output;
    int pkt_offset, i = 0;
    int ip_len, http_len, ip_proto;

    int src_port, dst_port, tcp_flags;

    char buf[BUFSIZE], my_time[STRSIZE];
    char src_ip[STRSIZE], dst_ip[STRSIZE];
    char host[STRSIZE], uri[BUFSIZE];

    //初始化
    file_header = (pcap_file_header *)malloc(sizeof(pcap_file_header));
    ptk_header = (pcap_pkthdr *)malloc(sizeof(pcap_pkthdr));
    mac_header = (FramHeader_t *)malloc(sizeof(FramHeader_t));
    ip_header = (IPHeader_t *)malloc(sizeof(IPHeader_t));
    tcp_header = (TCPHeader_t *)malloc(sizeof(TCPHeader_t));

    /*memset(buf, 0, sizeof(buf));*/

    //
    if ((fp = fopen(FILE_NAME, "r")) == NULL)
    {
        printf("error: can not open pcap file\n");
        exit(0);
    }

    if ((output = fopen("output.txt", "w+")) == NULL)
    {
        printf("error: can not open output file\n");
        exit(0);
    }

    //开始读数据包
    pkt_offset = 24; // pcap文件头结构 24个字节

    // 打印pcap文件头信息
    fread(&file_header, sizeof(pcap_file_header), 1, fp);
    if (file_header != NULL)
    {
        printf("=====================\n"
               "magic:0x%0x\n"
               "version_major:%u\n"
               "version_minor:%u\n"
               "thiszone:%d\n"
               "sigfigs:%u\n"
               "snaplen:%u\n"
               "linktype:%u\n"
               "=====================\n",
               file_header->magic,
               file_header->version_major,
               file_header->version_minor,
               file_header->thiszone,
               file_header->sigfigs,
               file_header->snaplen,
               file_header->linktype);
    }

    while (fseek(fp, pkt_offset, SEEK_SET) == 0) //遍历数据包
    {
        i++;
        // pcap_pkt_header 16 byte
        memset(ptk_header, 0, sizeof(struct pcap_pkthdr));
        if (fread(ptk_header, 16, 1, fp) != 1) //读pcap数据包头结构
        {
            printf("\nread end of pcap file\n");
            break;
        }

        pkt_offset += 16 + ptk_header->caplen; //下一个数据包的偏移值

        if (ptk_header != NULL)
        {
            printf("=====================\n"
                   "ts.timestamp_s:%u\n"
                   "ts.timestamp_ms:%u\n"
                   "capture_len:%u\n"
                   "len:%d\n"
                   "=====================\n",
                   ptk_header->ts.tv_sec,
                   ptk_header->ts.tv_usec,
                   ptk_header->caplen,
                   ptk_header->len);
        }

        //读取pcap包时间戳，转换成标准格式时间
        struct tm *timeinfo;
        time_t t = (time_t)(ptk_header->ts.tv_sec);
        timeinfo = localtime(&t);

        strftime(my_time, sizeof(my_time), "%Y-%m-%d %H:%M:%S", timeinfo); //获取时间
        // printf("%s\n", my_time);

        //数据帧头 14字节
        fseek(fp, 14, SEEK_CUR); //忽略数据帧头

        // IP数据报头 20字节
        memset(ip_header, 0, sizeof(IPHeader_t));
        if (fread(ip_header, sizeof(IPHeader_t), 1, fp) != 1)
        {
            printf("%d: can not read ip_header\n", i);
            break;
        }

        inet_ntop(AF_INET, (void *)&(ip_header->SrcIP), src_ip, 16);

        inet_ntop(AF_INET, (void *)&(ip_header->DstIP), dst_ip, 16);

        ip_proto = ip_header->Protocol;

        printf("time:%s, src_ip:%s, dst_ip:%s, ip protocol:%d\n", my_time, src_ip, dst_ip, ip_proto);
        ip_len = ip_header->TotalLen; // IP数据报总长度

        if (ip_proto != 6) //判断是否是 TCP 协议
        {
            continue;
        }

        // TCP头 20字节
        //  if (fread(tcp_header, sizeof(TCPHeader_t), 1, fp) != 1)
        //  {
        //      printf("%d: can not read ip_header\n", i);
        //      break;
        //  }
        //  printf("AAA\n");
        //  src_port = ntohs(tcp_header->SrcPort);
        //  dst_port = ntohs(tcp_header->DstPort);
        //  tcp_flags = tcp_header->Flags;
        //  printf("%d:  src=%x\n", i, tcp_flags);
        //  if (tcp_flags == 0x18) // (PSH, ACK) 3路握手成功后
        //  {
        //     if (dst_port == 80) // HTTP GET请求
        //     {
        //         http_len = ip_len - 40; //http 报文长度
        //         match_http(fp, "Host: ", "\r\n", host, http_len); //查找 host 值
        //         match_http(fp, "GET ", "HTTP", uri, http_len); //查找 uri 值
        //         sprintf(buf, "%d:  %s  src = %s : %d  dst = %s : %d  %s%s\r\n", i, my_time, src_ip, src_port, dst_ip, dst_port, host, uri);
        //         //printf("%s", buf);
        //         if (fwrite(buf, strlen(buf), 1, output) != 1)
        //         {
        //             printf("output file can not write");
        //             break;
        //         }
        //     }
        //  }
    } // end while

    fclose(fp);

    // fclose(output);

    // free(file_header);
    free(ptk_header);
    free(ip_header);
    free(tcp_header);
    return 0;
}

//查找 HTTP 信息

void match_http(FILE *fp, char *head_str, char *tail_str, char *buf, int total_len)
{
    int i;
    int http_offset;
    int head_len, tail_len, val_len;
    char head_tmp[STRSIZE], tail_tmp[STRSIZE];
    //初始化
    memset(head_tmp, 0, sizeof(head_tmp));
    memset(tail_tmp, 0, sizeof(tail_tmp));
    head_len = strlen(head_str);
    tail_len = strlen(tail_str);
    //查找 head_str

    http_offset = ftell(fp);                 //记录下HTTP报文初始文件偏移
    while ((head_tmp[0] = fgetc(fp)) != EOF) //逐个字节遍历
    {
        if ((ftell(fp) - http_offset) > total_len) //遍历完成
        {
            sprintf(buf, "can not find %s \r\n", head_str);
            exit(0);
        }
        if (head_tmp[0] == *head_str) //匹配到第一个字符
        {
            for (i = 1; i < head_len; i++) //匹配 head_str 的其他字符
            {
                head_tmp[i] = fgetc(fp);
                if (head_tmp[i] != *(head_str + i))
                    break;
            }
            if (i == head_len) //匹配 head_str 成功，停止遍历
                break;
        }
    }
    // printf("head_tmp=%s \n", head_tmp);

    //查找 tail_str
    val_len = 0;
    while ((tail_tmp[0] = fgetc(fp)) != EOF) //遍历
    {
        if ((ftell(fp) - http_offset) > total_len) //遍历完成
        {
            sprintf(buf, "can not find %s \r\n", tail_str);
            exit(0);
        }
        buf[val_len++] = tail_tmp[0]; //用buf 存储 value 直到查找到 tail_str
        if (tail_tmp[0] == *tail_str) //匹配到第一个字符
        {
            for (i = 1; i < tail_len; i++) //匹配 head_str 的其他字符
            {
                tail_tmp[i] = fgetc(fp);
                if (tail_tmp[i] != *(tail_str + i))
                    break;
            }

            if (i == tail_len) //匹配 head_str 成功，停止遍历
            {
                buf[val_len - 1] = 0; //清除多余的一个字符
                break;
            }
        }
    }

    // printf("val=%s\n", buf);

    fseek(fp, http_offset, SEEK_SET); //将文件指针 回到初始偏移
}
