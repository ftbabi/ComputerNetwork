#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/if_ether.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <string.h>

#define MAX_IP_LIST 4
#define MAX_IP_LEN  64
#define OUTPUT_BUF_MAX 4096
#define BUFFER_MAX 2048
#define MODE 0 // 1 filter

/* 6 bytes Mac address */
typedef struct mac_address {
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
    u_char byte5;
    u_char byte6;
}MAC_ADDR;

/* Enthernet header */
typedef struct enthernet_Header {
    MAC_ADDR    daddr;      // Source mac address
    MAC_ADDR    saddr;      // Destination mac address
    u_short     type;       // Type
}ENT_HEADER;

/* 4 bytes IP address */
typedef struct ip_address {
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
}IP_ADDR;

/* ARP header */
typedef struct apr_header {
    u_short ar_hrd;         // ARP hardware type
    u_short ar_pro;         // Protocol type
    u_char  ar_hln;         // Hardware size/length
    u_char  ar_pln;         // Protocol size/length
    u_short ar_op;          // Opcode
}APR_HEADER;

/* ARP message */
typedef struct arp_message {
    APR_HEADER  arp_hdr;    // APR header
    MAC_ADDR    arp_sha;    // Sender MAC address
    IP_ADDR     arp_spa;    // Sender IP address
    MAC_ADDR    arp_tha;    // Target MAC address
    IP_ADDR     arp_tpa;    // Target IP address
}ARP_MSG;

/* ICMP common header */
typedef struct icmp_header {
    u_char  type;           // Type
    u_char  code;           // Code
    u_short cksum;          // Check sum
    u_short id;             // Identification
    u_short seq;            // Sequence
}ICMP_HEADER;

/* IPv4 header */
typedef struct ip_header {
    u_char  ver_ihl;        // Version (4 bits) + Internet header length (4 bits)
    u_char  tos;            // Type of service
    u_short tlen;           // Total length
    u_short identification; // Identification
    u_short flags_fo;       // Flags (3 bits) + Fragment offset (13 bits)
    u_char  ttl;            // Time to live
    u_char  proto;          // Protocol
    u_short crc;            // Header checksum
    IP_ADDR saddr;          // Source address
    IP_ADDR daddr;          // Destination address
}IP_HEADER;

/* TCP header */
typedef struct tcp_header {
    u_short sport;          // Source port
    u_short dpost;          // Destination port
    u_int   seq;            // Sequence number field
    u_int   ack;            // Acknowledgment number field
    u_short flag;           // 4bits header length fiedl and 6bits reserved and 6bits flag
    u_short wnd_size;       // Window size
    u_short chk_sum;        // Checksum
    u_short urgt_p;         // Urgent data pointer field
}TCP_HEADER;

/* UDP header*/
typedef struct udp_header{
    u_short sport;          // Source port
    u_short dport;          // Destination port
    u_short len;            // Datagram length
    u_short crc;            // Checksum
}UDP_HEADER;

int parse_icmp(char *buffer, char ip_list[][MAX_IP_LEN], char *output_buf) {
    ICMP_HEADER *icmp_header = (struct ICMP_HEADER *) buffer;
    char inner_buf[BUFFER_MAX];

    strncat(output_buf, "Internet Control Message Protocol\n", OUTPUT_BUF_MAX -strlen(output_buf));
    snprintf(inner_buf, BUFFER_MAX, "==>Type: %d ", icmp_header->type);
    strncat(output_buf, inner_buf, OUTPUT_BUF_MAX-strlen(output_buf));
    if(icmp_header->type == 8 && icmp_header->code == 0) {
        strncat(output_buf, "(Echo (ping) request)\n==>Code: 0\n", OUTPUT_BUF_MAX-strlen(output_buf));
    }
    else if(icmp_header->type == 0 && icmp_header->code == 0) {
        strncat(output_buf, "(Echo (ping) response)\n==>Code: 0\n", OUTPUT_BUF_MAX-strlen(output_buf));
    }
    else {
        snprintf(inner_buf, BUFFER_MAX, "\n==>Code: %d\n", icmp_header->code);
        strncat(output_buf, inner_buf, OUTPUT_BUF_MAX-strlen(output_buf));
    }
    snprintf(inner_buf, BUFFER_MAX, "==> Checksum: 0x%04x\n"
            "==> Indentifier: %d (0x%04x)\n"
            "==> Sequence number: %d (0x%04x)\n",
             htons(icmp_header->cksum),
             htons(icmp_header->id), htons(icmp_header->id),
             htons(icmp_header->seq), htons(icmp_header->seq)

    );
    strncat(output_buf, inner_buf, OUTPUT_BUF_MAX-strlen(output_buf));

    return 0;
}

int parse_tcp(char *buffer, char ip_list[][MAX_IP_LEN], char *output_buf) {
    TCP_HEADER *tcp_header = (struct TCP_HEADER *) buffer;
    char inner_buf[BUFFER_MAX];

    snprintf(inner_buf, BUFFER_MAX, "Transmission Control Protocol, Src Port: %d, Dst Port: %d, Seq: %d\n"
            "==> Source Port: %d\n"
            "==> Destination Port: %d\n"
            "==> Sequence number: %d\n"
            "==> Acknowledgment number: %d\n"
            "==> Header Length: %d bytes (%d)\n"
            "==> Flags: 0x%03x\n"
            "==> Window size value: %d\n"
            "==> Checksum: 0x%04x\n"
            "==> Urgent pointer: %d\n",
             htons(tcp_header->sport), htons(tcp_header->dpost), htonl(tcp_header->seq),
             htons(tcp_header->sport),
             htons(tcp_header->dpost),
             htonl(tcp_header->seq),
             htonl(tcp_header->ack),
             ((htons(tcp_header->flag)&0xF000) >> 12)*4, (htons(tcp_header->flag)&0xF000) >> 12,
             htons(tcp_header->flag)&0x0FFF,
             htons(tcp_header->wnd_size),
             htons(tcp_header->chk_sum),
             htons(tcp_header->urgt_p)
    );
    strncat(output_buf, inner_buf, OUTPUT_BUF_MAX-strlen(output_buf));

    return 0;
}

int parse_udp(char *buffer, char ip_list[][MAX_IP_LEN], char *output_buf) {
    UDP_HEADER *udp_header = (struct UDP_HEADER *) buffer;
    char inner_buf[BUFFER_MAX];

    snprintf(inner_buf, BUFFER_MAX, "User Datagram Protocol, Src Port: %d, Dst Port: %d\n"
            "==> Source Port: %d\n"
            "==> Destination Port: %d\n"
            "==> Length: %d\n"
            "==> Checksum: 0x%04x\n",
            htons(udp_header->sport), htons(udp_header->dport),
            htons(udp_header->sport),
            htons(udp_header->dport),
            htons(udp_header->len),
            htons(udp_header->crc)
    );
    strncat(output_buf, inner_buf, OUTPUT_BUF_MAX-strlen(output_buf));

    return 0;
}

int parse_ip(char *buffer, char ip_list[][MAX_IP_LEN], char *output_buf){
    IP_HEADER *ip_header;
    ip_header = (struct IP_HEADER *)buffer;
    char inner_buf[BUFFER_MAX];
    int i = 0;

    if(MODE) {
        snprintf(inner_buf, BUFFER_MAX, "%d.%d.%d.%d",
                 ip_header->daddr.byte1, ip_header->daddr.byte2, ip_header->daddr.byte3,
                 ip_header->daddr.byte4
        );
        // if the destination is local ip
        for(i = 0; i < MAX_IP_LIST; ++i) {
            if(strncmp(ip_list[i], inner_buf, strlen(inner_buf)) == 0) {
                break;
            }
        }
        if(i == MAX_IP_LIST) {
            return -1;
        }
    }

    snprintf(inner_buf, BUFFER_MAX, "Internet Protocol Version %d, Src: %d.%d.%d.%d, Dst: %d.%d.%d.%d\n",
           ((ip_header->ver_ihl & 0xF0) >> 4),
           ip_header->saddr.byte1, ip_header->saddr.byte2, ip_header->saddr.byte3,
           ip_header->saddr.byte4,
           ip_header->daddr.byte1, ip_header->daddr.byte2, ip_header->daddr.byte3,
           ip_header->daddr.byte4
    );
    strncat(output_buf, inner_buf, OUTPUT_BUF_MAX-strlen(output_buf));

    snprintf(inner_buf, BUFFER_MAX, "==> Header Length: %d bytes (%d)\n"
                   "==> Type of service: %02x\n"
                   "==> Total Length: %d\n"
                   "==> Identification: 0x%04x\n"
                   "==> Flags: 0x%04x\n"
                   "==> Time to live: %d\n",
           (ip_header->ver_ihl & 0x0F)*4, (ip_header->ver_ihl & 0x0F),
           ip_header->tos,
           htons(ip_header->tlen),
           htons(ip_header->identification),
           htons(ip_header->flags_fo),
           ip_header->ttl
    );
    strncat(output_buf, inner_buf, OUTPUT_BUF_MAX-strlen(output_buf));

    strncat(output_buf, "==> Protocol: ", OUTPUT_BUF_MAX-strlen(output_buf));
    switch(ip_header->proto){
        case IPPROTO_ICMP:strncat(output_buf, "ICMP", OUTPUT_BUF_MAX-strlen(output_buf));break;
        case IPPROTO_IGMP:strncat(output_buf, "IGMP", OUTPUT_BUF_MAX-strlen(output_buf));break;
        case IPPROTO_IPIP:strncat(output_buf, "IPIP", OUTPUT_BUF_MAX-strlen(output_buf));break;
        case IPPROTO_TCP:strncat(output_buf, "TCP", OUTPUT_BUF_MAX-strlen(output_buf));break;
        case IPPROTO_UDP:strncat(output_buf, "UDP", OUTPUT_BUF_MAX-strlen(output_buf));break;
        default:strncat(output_buf, "Pls query yourself", OUTPUT_BUF_MAX-strlen(output_buf));
    }
    snprintf(inner_buf, BUFFER_MAX, " (%d)\n"
                   "==> Header checksum: 0x%04x\n",
           ip_header->proto,
           htons(ip_header->crc)
    );
    strncat(output_buf, inner_buf, OUTPUT_BUF_MAX-strlen(output_buf));

    switch(ip_header->proto){
        case IPPROTO_ICMP: parse_icmp(&buffer[20], ip_list, output_buf); break;
        case IPPROTO_IGMP: break;
        case IPPROTO_IPIP: break;
        case IPPROTO_TCP: parse_tcp(&buffer[20], ip_list, output_buf); break;
        case IPPROTO_UDP: parse_udp(&buffer[20], ip_list, output_buf); break;
        default:
            break;
    }

    return 0;
}

int parse_arp(char *buffer, char ip_list[][MAX_IP_LEN], char *output_buf) {
    ARP_MSG *arp_msg = (struct ARP_MSG *) buffer;
    char inner_buf[BUFFER_MAX];
    int i = 0;

    if(MODE) {
        snprintf(inner_buf, BUFFER_MAX, "%d.%d.%d.%d",
                 arp_msg->arp_tpa.byte1, arp_msg->arp_tpa.byte2, arp_msg->arp_tpa.byte3, arp_msg->arp_tpa.byte4
        );
        // if the destination is local ip
        for(i = 0; i < MAX_IP_LIST; ++i) {
            if(strncmp(ip_list[i], inner_buf, strlen(inner_buf)) == 0) {
                break;
            }
        }
        if(i == MAX_IP_LIST) {
            return -1;
        }
    }

    strncat(output_buf, "Address Resolution Protocol ", OUTPUT_BUF_MAX-strlen(output_buf));
    if(htons(arp_msg->arp_hdr.ar_op) == 1) {
        strncat(output_buf, "(request)", OUTPUT_BUF_MAX-strlen(output_buf));
    }
    else {
        strncat(output_buf, "(respond)", OUTPUT_BUF_MAX-strlen(output_buf));
    }
    strncat(output_buf, "\n==> Hardware type: ", OUTPUT_BUF_MAX-strlen(output_buf));
    if(htons(arp_msg->arp_hdr.ar_hrd) == 1) {
        strncat(output_buf, "Ethernet ", OUTPUT_BUF_MAX-strlen(output_buf));
    }
    else {
        strncat(output_buf, "Unknown ", OUTPUT_BUF_MAX-strlen(output_buf));
    }
    snprintf(inner_buf, BUFFER_MAX, "(%d)", htons(arp_msg->arp_hdr.ar_hrd));
    strncat(output_buf, inner_buf, OUTPUT_BUF_MAX-strlen(output_buf));
    strncat(output_buf, "\n==> Protocol type: ", OUTPUT_BUF_MAX-strlen(output_buf));
    switch (htons(arp_msg->arp_hdr.ar_pro)) {
        case 0x0800: strncat(output_buf, "IP ", OUTPUT_BUF_MAX-strlen(output_buf)); break;
        case 0x0806: strncat(output_buf, "ARP ", OUTPUT_BUF_MAX-strlen(output_buf)); break;
        default: strncat(output_buf, "Unknown ", OUTPUT_BUF_MAX-strlen(output_buf)); break;
    }
    snprintf(inner_buf, BUFFER_MAX, "(0x%04x)", htons(arp_msg->arp_hdr.ar_pro));
    strncat(output_buf, inner_buf, OUTPUT_BUF_MAX-strlen(output_buf));
    snprintf(inner_buf, BUFFER_MAX, "\n==> Hardware size: %d\n"
                   "==> Protocol size: %d\n"
                   "==> Opcode: ",
           arp_msg->arp_hdr.ar_hln, arp_msg->arp_hdr.ar_pln
    );
    strncat(output_buf, inner_buf, OUTPUT_BUF_MAX-strlen(output_buf));

    if(htons(arp_msg->arp_hdr.ar_op) == 1) {
        strncat(output_buf, "request", OUTPUT_BUF_MAX-strlen(output_buf));
    }
    else {
        strncat(output_buf, "respond", OUTPUT_BUF_MAX-strlen(output_buf));
    }
    snprintf(inner_buf, BUFFER_MAX, " (%d)", htons(arp_msg->arp_hdr.ar_op));
    strncat(output_buf, inner_buf, OUTPUT_BUF_MAX-strlen(output_buf));
    snprintf(inner_buf, BUFFER_MAX, "\n==> Sender MAC address: %.2x:%02x:%02x:%02x:%02x:%02x\n"
                   "==> Sender IP address: %d.%d.%d.%d\n"
                   "==> Target MAC address: %.2x:%02x:%02x:%02x:%02x:%02x\n"
                   "==> Target IP address: %d.%d.%d.%d\n",
           arp_msg->arp_sha.byte1, arp_msg->arp_sha.byte2, arp_msg->arp_sha.byte3,
           arp_msg->arp_sha.byte4, arp_msg->arp_sha.byte5, arp_msg->arp_sha.byte6,
           arp_msg->arp_spa.byte1, arp_msg->arp_spa.byte2, arp_msg->arp_spa.byte3, arp_msg->arp_spa.byte4,
           arp_msg->arp_tha.byte1, arp_msg->arp_tha.byte2, arp_msg->arp_tha.byte3,
           arp_msg->arp_tha.byte4, arp_msg->arp_tha.byte5, arp_msg->arp_tha.byte6,
           arp_msg->arp_tpa.byte1, arp_msg->arp_tpa.byte2, arp_msg->arp_tpa.byte3, arp_msg->arp_tpa.byte4
    );
    strncat(output_buf, inner_buf, OUTPUT_BUF_MAX-strlen(output_buf));

    return 0;
}

int parse_enther(char *buffer, char ip_list[][MAX_IP_LEN]) {
    // 注意顺序，先判断是不是ip，再进行解析输出。就很烦
    char output_buf[OUTPUT_BUF_MAX] = "\n====================*===================\n";
    char inner_buf[BUFFER_MAX] = "";
    ENT_HEADER *ent_header = (struct ENT_HEADER *) buffer;
    int ret_flag = -1;

    strncat(output_buf, "Ethernet, ", OUTPUT_BUF_MAX-strlen(output_buf));
    snprintf(inner_buf, BUFFER_MAX, "Src: %.2x:%02x:%02x:%02x:%02x:%02x, "
                   "Dst: %.2x:%02x:%02x:%02x:%02x:%02x. Type: ",
           ent_header->saddr.byte1, ent_header->saddr.byte2, ent_header->saddr.byte3,
           ent_header->saddr.byte4, ent_header->saddr.byte5, ent_header->saddr.byte6,
           ent_header->daddr.byte1, ent_header->daddr.byte2, ent_header->daddr.byte3,
           ent_header->daddr.byte4, ent_header->daddr.byte5, ent_header->daddr.byte6
    );
    strncat(output_buf, inner_buf, OUTPUT_BUF_MAX-strlen(output_buf));
    switch (htons(ent_header->type)) {
        case 0x0800:
            snprintf(inner_buf, BUFFER_MAX, "IPv4 (%04x)\n", htons(ent_header->type));
            strncat(output_buf, inner_buf, OUTPUT_BUF_MAX-strlen(output_buf));
            ret_flag = parse_ip(&buffer[14], ip_list, output_buf);
            break;
        case 0x0806:
            snprintf(inner_buf, BUFFER_MAX, "ARP (%04x)\n", htons(ent_header->type));
            strncat(output_buf, inner_buf, OUTPUT_BUF_MAX-strlen(output_buf));
            ret_flag = parse_arp(&buffer[14], ip_list, output_buf);
            break;
        default:
            snprintf(inner_buf, BUFFER_MAX, "Unknown enthernet type: %04x\n", ent_header->type);
            ret_flag = -1;
            break;
    }

    if(ret_flag < 0) {
        return -1;
    }

    printf("%s", output_buf);
    return 0;
}

int get_local_ip(char ip[][MAX_IP_LEN])
{
    int fd, intrface, retn = 0, i = 0;
    struct ifreq buf[INET_ADDRSTRLEN];
    struct ifconf ifc;
    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) >= 0)
    {
        ifc.ifc_len = sizeof(buf);
        // caddr_t,linux内核源码里定义的：typedef void *caddr_t；
        ifc.ifc_buf = (caddr_t)buf;
        if (!ioctl(fd, SIOCGIFCONF, (char *)&ifc))
        {
            intrface = ifc.ifc_len/sizeof(struct ifreq);
            for(i = 0; i < intrface && i < MAX_IP_LIST; ++i) {
                if (!(ioctl(fd, SIOCGIFADDR, (char *)&buf[i])))
                {
                    strncpy(ip[i], (inet_ntoa(((struct sockaddr_in*)(&buf[i].ifr_addr))->sin_addr)), MAX_IP_LEN);
                    printf("DEBUG IP:%s\n", ip[i]);
                }
            }
        }
        close(fd);
        return i;
    }

    return -1;
}

int main(int argc,char* argv[]){
    int sock_fd = 0;
    int n_read;
    char buffer[BUFFER_MAX];
    ENT_HEADER *ent_header;
    IP_HEADER *ip_header;
    char ip_list[MAX_IP_LIST][MAX_IP_LEN];
    char *tcp_head;
    char *udp_head;
    char *icmp_head;
    get_local_ip(ip_list);
    if((sock_fd=socket(PF_PACKET,SOCK_RAW,htons(ETH_P_ALL)))<0) // htons()作用是将端口号由主机字节序转换为网络字节序的整数值。(host to net)
    {
        printf("error create raw socket\n");
        return -1;
    }
    while(1){
        n_read = recvfrom(sock_fd,buffer,2048,0,NULL,NULL);
        if(n_read < 42)
        {
            printf("error when recv msg \n");
            return -1;
        }
        parse_enther(buffer, ip_list);
//        ent_header = (struct ENT_HEADER *) buffer;
//        printf("MAC address: %.2x:%02x:%02x:%02x:%02x:%02x "
//                       "==> %.2x:%02x:%02x:%02x:%02x:%02x\n",
//               ent_header->saddr.byte1, ent_header->saddr.byte2, ent_header->saddr.byte3,
//               ent_header->saddr.byte4, ent_header->saddr.byte5, ent_header->saddr.byte6,
//               ent_header->daddr.byte1, ent_header->daddr.byte2, ent_header->daddr.byte3,
//               ent_header->daddr.byte4, ent_header->daddr.byte5, ent_header->daddr.byte6
//        );
//
//        ip_header = (struct IP_HEADER *) &buffer[14];
//        printf("IP:%d.%d.%d.%d==> %d.%d.%d.%d\n",
//               ip_header->saddr.byte1, ip_header->saddr.byte2, ip_header->saddr.byte3,
//               ip_header->saddr.byte4,
//               ip_header->daddr.byte1, ip_header->daddr.byte2, ip_header->daddr.byte3,
//               ip_header->daddr.byte4
//        );
//        printf("Protocol:");
//        switch(ip_header->proto){
//            case IPPROTO_ICMP:printf("icmp\n");break;
//            case IPPROTO_IGMP:printf("igmp\n");break;
//            case IPPROTO_IPIP:printf("ipip\n");break;
//            case IPPROTO_TCP:printf("tcp\n");break;
//            case IPPROTO_UDP:printf("udp\n");break;
//            default:printf("Pls query yourself\n");
//        }
    }
    return -1;
}