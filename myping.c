#include <stdio.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <unistd.h>
#include <signal.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/time.h>
#include <string.h>
#include <netdb.h>
#include <pthread.h>


#define PACKET_SEND_MAX_NUM 64

typedef struct ping_packet_status
{
    struct timeval begin_time; // 包发送时间
    struct timeval end_time; // 包结束时间
    int flag;   //发送标志,1为已发送
    int seq;     //包的序列号
}ping_packet_status;



ping_packet_status ping_packet[PACKET_SEND_MAX_NUM];

int alive;
int rawsock;
int send_count;
int recv_count;
pid_t pid;

/*
 * struct sockaddr_in {
 *      __uint8_t	sin_len;
 *      sa_family_t	sin_family;     // 地址族
 *      in_port_t	sin_port;       // 16位TCP/UDP端口号
 *      struct	in_addr sin_addr;   // 32位IP地址
 *      char		sin_zero[8];    // 不使用
 * };
 * struct in_addr {
 *      in_addr_t s_addr;           // 32位IPv4地址
 * };
 */
struct sockaddr_in dest;

/*
 * _STRUCT_TIMEVAL
 * {
 *      __darwin_time_t	        tv_sec;	        // seconds
 *      __darwin_suseconds_t    tv_usec;        // and microseconds
 * };
 */
struct timeval start_time;
struct timeval end_time;
struct timeval time_interval;

/*校验和算法*/
unsigned short cal_chksum(unsigned short *addr,int len)
{
    int sum=0;
    unsigned short *w=addr;
    unsigned short answer=0;

    //把ICMP报头二进制数据以2字节为单位累加起来
    while(len > 1) {
        sum += *w++;
        len -= 2;
    }
    //若ICMP报头为奇数个字节，会剩下最后一字节。把最后一个字节视为一个2字节数据的高字节，这个2字节数据的低字节为0，继续累加
    if(len == 1) {
        *(unsigned char *)(&answer) = *(unsigned char *)w;
        sum += answer;
    }
    // 因为要回卷，而且长度为2L的sum，L+L的长度可能大于L但小于2L，所以这里有两次类似回卷的操作
    sum = (sum>>16)+(sum&0xffff);
    sum += (sum>>16);
    answer = ~sum;
    return answer;
}

struct timeval cal_time_offset(struct timeval begin, struct timeval end)
{
    struct timeval ans;
    ans.tv_sec = end.tv_sec - begin.tv_sec;
    ans.tv_usec = end.tv_usec - begin.tv_usec;
    if(ans.tv_usec < 0) //如果接收时间的usec小于发送时间的usec，则向sec域借位
    {
        ans.tv_sec--;
        ans.tv_usec+=1000000;
    }
    return ans;
}

void icmp_pack(struct icmp* icmphdr, int seq, int length)
{
    int i = 0;

    // 这里只是请求回显报文结构，包括类型、代码、校验和、标识符、序列号
    icmphdr->icmp_type = ICMP_ECHO;
    icmphdr->icmp_code = 0;
    icmphdr->icmp_cksum = 0;
    icmphdr->icmp_seq = seq;
    icmphdr->icmp_id = pid & 0xffff; // 标识符
    for(i=0;i<length;i++)
    {
        icmphdr->icmp_data[i] = i;
    }

    icmphdr->icmp_cksum = cal_chksum((unsigned short*)icmphdr, length);
}

int icmp_unpack(char* buf, int len)
{
    /*
     * 1. 解包，提取icmp并判断合法性
     * 2. 判断是不是我们发出去的包，即比较type、id
     * 3. 计算时间
     */
    int iphdr_len;
    struct timeval begin_time, recv_time, offset_time;
    int rtt;  //round trip time

    struct ip* ip_hdr = (struct ip *)buf;
    iphdr_len = ip_hdr->ip_hl*4; // 查阅可知，这个数字的单位是32bit（4字节），所以要乘以4表示一共多少字节
    struct icmp* icmp = (struct icmp*)(buf+iphdr_len);
    len-=iphdr_len;  //icmp包长度
    if(len < 8)   //判断长度是否为ICMP包长度，因为除去占位字段至少8字节
    {
        fprintf(stderr, "Invalid icmp packet.Its length is less than 8\n");
        return -1;
    }

    //判断该包是ICMP回送回答包且该包是我们发出去的
    if((icmp->icmp_type == ICMP_ECHOREPLY) && (icmp->icmp_id == (pid & 0xffff)))
    {
        if((icmp->icmp_seq < 0) || (icmp->icmp_seq > PACKET_SEND_MAX_NUM))
        {
            fprintf(stderr, "icmp packet seq is out of range!\n");
            return -1;
        }

        ping_packet[icmp->icmp_seq].flag = 0;
        begin_time = ping_packet[icmp->icmp_seq].begin_time;
        gettimeofday(&recv_time, NULL);

        offset_time = cal_time_offset(begin_time, recv_time);
        rtt = offset_time.tv_sec*1000 + offset_time.tv_usec/1000; //毫秒为单位

        printf("%d byte from %s: icmp_seq=%u ttl=%d rtt=%d ms\n",
               len, inet_ntoa(ip_hdr->ip_src), icmp->icmp_seq, ip_hdr->ip_ttl, rtt);

    }
    else
    {
        fprintf(stderr, "Invalid ICMP packet! Its id is not matched!\n");
        return -1;
    }
    return 0;
}

void ping_send()
{
    char send_buf[128];
    memset(send_buf, 0, sizeof(send_buf));
    gettimeofday(&start_time, NULL); //记录第一个ping包发出的时间，用于最后的时候输出总共时间
    while(alive)
    {
        int size = 0;
        gettimeofday(&(ping_packet[send_count].begin_time), NULL);
        ping_packet[send_count].flag = 1; //将该标记为设置为该包已发送

        icmp_pack((struct icmp*)send_buf, send_count, 64); //封装icmp包
        // int sendto ( socket s , const void * msg, int len, unsigned int flags, const struct sockaddr * to , int tolen ) ;
        size = sendto(rawsock, send_buf, 64, 0, (struct sockaddr*)&dest, sizeof(dest));
        send_count++; //记录发出ping包的数量
        if(size < 0)
        {
            fprintf(stderr, "send icmp packet fail!\n");
            continue;
        }

        sleep(1);
    }
}

void ping_recv()
{
    struct timeval tv;
    tv.tv_usec = 200;  //设置select函数的超时时间为200us
    tv.tv_sec = 0;
    fd_set read_fd;
    char recv_buf[512];
    memset(recv_buf, 0 ,sizeof(recv_buf));
    while(alive)
    {
        int ret = 0;
        FD_ZERO(&read_fd);
        FD_SET(rawsock, &read_fd);

        // int select(int nfds,  fd_set* readset,  fd_set* writeset,  fe_set* exceptset,  struct timeval* timeout);
        // select选取处于就绪状态的sock，并返回可以读取操作的文件个数
        ret = select(rawsock+1, &read_fd, NULL, NULL, &tv);
        switch(ret)
        {
            case -1:
                fprintf(stderr,"fail to select!\n");
                break;
            case 0:
                break;
            default:
            {
                int size = recv(rawsock, recv_buf, sizeof(recv_buf), 0);
                if(size < 0)
                {
                    fprintf(stderr,"recv data fail!\n");
                    continue;
                }

                ret = icmp_unpack(recv_buf, size); //对接收的包进行解封
                if(ret == -1)  //不是属于自己的icmp包，丢弃不处理
                {
                    continue;
                }
                recv_count++; //接收包计数
            }
                break;
        }

    }
}

void icmp_sigint(int signo)
{
    alive = 0;
    gettimeofday(&end_time, NULL);
    time_interval = cal_time_offset(start_time, end_time);
}

void ping_stats_show()
{
    long time = time_interval.tv_sec*1000+time_interval.tv_usec/1000;
    /*注意除数不能为零，这里send_count有可能为零，所以运行时提示错误*/
    printf("%d packets transmitted, %d recieved, %d%c packet loss, time %ldms\n",
           send_count, recv_count, (send_count-recv_count)*100/send_count, '%', time);
}


int main(int argc, char* argv[])
{
    int size = 128*1024;//128k
    struct protoent* protocol = NULL;
    char dest_addr_str[80];
    memset(dest_addr_str, 0, 80);
    unsigned int inaddr = 1;
    struct hostent* host = NULL;

    pthread_t send_id,recv_id;

    if(argc < 2)
    {
        printf("Invalid IP ADDRESS!\n");
        return -1;
    }

    protocol = getprotobyname("icmp"); //获取协议类型ICMP
    if(protocol == NULL)
    {
        printf("Fail to getprotobyname!\n");
        return -1;
    }

    memcpy(dest_addr_str, argv[1], strlen(argv[1])+1);

    rawsock = socket(AF_INET,SOCK_RAW,protocol->p_proto);
    if(rawsock < 0)
    {
        printf("Fail to create socket!\n");
        return -1;
    }

    pid = getpid();

    setsockopt(rawsock, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size)); //增大接收缓冲区至128K

    // 置字节字符串s的前n个字节为零且包括‘\0’
    bzero(&dest,sizeof(dest));
    dest.sin_family = AF_INET;
    inaddr = inet_addr(argv[1]);
    if(inaddr == INADDR_NONE)   //判断用户输入的是否为IP地址还是域名，域名解析
    {
        //输入的是域名地址
        host = gethostbyname(argv[1]);
        if(host == NULL)
        {
            printf("Fail to gethostbyname!\n");
            return -1;
        }

        memcpy((char*)&dest.sin_addr, host->h_addr, host->h_length);
    }
    else
    {
        memcpy((char*)&dest.sin_addr, &inaddr, sizeof(inaddr));//输入的是IP地址
    }
    inaddr = dest.sin_addr.s_addr;
    printf("PING %s, (%d.%d.%d.%d) 56(84) bytes of data.\n",dest_addr_str,
           (inaddr&0x000000ff), (inaddr&0x0000ff00)>>8,
           (inaddr&0x00ff0000)>>16, (inaddr&0xff000000)>>24);

    alive = 1;  //控制ping的发送和接收

    signal(SIGINT, icmp_sigint);

    if(pthread_create(&send_id, NULL, (void*)ping_send, NULL))
    {
        printf("Fail to create ping send thread!\n");
        return -1;
    }

    if(pthread_create(&recv_id, NULL, (void*)ping_recv, NULL))
    {
        printf("Fail to create ping recv thread!\n");
        return -1;
    }

    pthread_join(send_id, NULL);//等待send ping线程结束后进程再结束
    pthread_join(recv_id, NULL);//等待recv ping线程结束后进程再结束

    ping_stats_show();

    close(rawsock);
    return 0;

}