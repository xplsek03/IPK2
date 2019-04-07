// struktury a CRC, prevzato z https://www.tenouk.com/Module43a.html

#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h> // sleep()
#include <pthread.h>
#include <getopt.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/types.h>

#define PCKT_LEN 8192
#define PORT_RANGE_START 50000
#define PORT_RANGE_END 60000

struct ipheader {
    //#if BYTE_ORDER == LITTLE_ENDIAN 
    unsigned char iph_ihl, iph_ver;    /* header length */ /* version */
                     
    //#endif
    //#if BYTE_ORDER == BIG_ENDIAN 
    //unsigned char  iph_ver, iph_ihl;   /* version */ /* header length */
    //#endif
    unsigned char  iph_tos;         /* type of service */
    short   iph_len;         /* total length */
    __u_short iph_ident;          /* identification */
    short   iph_offset;         /* fragment offset field */
    #define IP_DF 0x4000        /* dont fragment flag */
    #define IP_MF 0x2000        /* more fragments flag */
    unsigned char  iph_ttl;         /* time to live */
    unsigned char  iph_protocol;           /* protocol */
    __u_short iph_chksum;         /* checksum */
    unsigned int iph_sourceip,iph_destip;  /* source and dest address */
};

struct tcpheader {
    unsigned short int tcph_srcport;
    unsigned short int tcph_destport;
    unsigned int       tcph_seqnum;
    unsigned int       tcph_acknum;
    unsigned char      tcph_reserved:4, tcph_offset:4;
    // unsigned char tcph_flags;
    unsigned int
        tcp_res1:4,      /*little-endian*/
        tcph_hlen:4,     /*length of tcp header in 32-bit words*/
        tcph_fin:1,      /*Finish flag "fin"*/
        tcph_syn:1,       /*Synchronize sequence numbers to start a connection*/
        tcph_rst:1,      /*Reset flag */
        tcph_psh:1,      /*Push, sends data to the application*/
        tcph_ack:1,      /*acknowledge*/
        tcph_urg:1,      /*urgent pointer*/
        tcph_res2:2;
    unsigned short int tcph_win;
    unsigned short int tcph_chksum;
    unsigned short int tcph_urgptr;
};

unsigned short csum(unsigned short *buf, int len);
void send_syn(int client, int target_port, char *target_address, char *addresses[], int address_count, int spoofed_port);
int portCount(int type, int *arr);