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
#include <stdbool.h>

#define PCKT_LEN 8192
#define PORT_RANGE_START 50000
#define PORT_RANGE_END 60000

struct thread_arguments {
        int client;
        int target_port; 
        char *target_address; 
        char **addresses;
        int address_count; 
        int spoofed_port;
};

/*struct ipheader {

    unsigned char  iph_tos;        
    short   iph_len;        
    __u_short iph_ident;    
    short   iph_offset;       
    #define IP_DF 0x4000     
    #define IP_MF 0x2000       
    unsigned char  iph_ttl;        
    unsigned char  iph_protocol;       
    __u_short iph_chksum;        
    unsigned int iph_sourceip,iph_destip;
};*/

struct tcpheader {
    unsigned short int tcph_srcport;
    unsigned short int tcph_destport;
    unsigned int       tcph_seqnum;
    unsigned int       tcph_acknum;
    unsigned char      tcph_reserved:4, tcph_offset:4;
    // unsigned char tcph_flags;
    unsigned int
        tcp_res1:4,     
        tcph_hlen:4,    
        tcph_fin:1,      
        tcph_syn:1,       
        tcph_rst:1,      
        tcph_psh:1,     
        tcph_ack:1,      
        tcph_urg:1,    
        tcph_res2:2;
    unsigned short int tcph_win;
    unsigned short int tcph_chksum;
    unsigned short int tcph_urgptr;
};

struct single_interface {
    char *name;
    char *ip;
    char *mask;
    bool usable;
};

struct ping_arguments {
    char *ip;
    char *target;
    int client;
    bool *ok;
    char *ifc;
};

struct ping_sniffer_arguments {
    char *ifc;
    char *ping_phrase;
    int client;
    bool *ok;
};

unsigned short csum(unsigned short *buf, int len);
void *send_syn(void *arg);
int portCount(int type, int *arr);
void *sniffer(void *arg, char *ifc);
void *ping_sniffer(void *arg);
struct single_interface **getInterface(int *interfaces_count);
void *ping(void *arg);
void ping_success(bool *ok, const struct pcap_pkthdr *header, const unsigned char *packet);