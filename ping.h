#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>
#include <pthread.h>
#include <getopt.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <ifaddrs.h>
#include <stdbool.h>

#define PACKETSIZE	64

struct packet
{
	struct icmphdr hdr;
	char msg[PACKETSIZE-sizeof(struct icmphdr)];
};

struct ping_arguments {
    char ip[16];
    char target[16];
    struct sockaddr_in *target_struct;
    int client;
    bool *ok;
    char ifc[20];
};

struct ping_callback_arguments {
    char ip[16];
    char target[16];
    int client;
    bool *ok;
    char ifc[20];
    pcap_t *sniff;
};

struct port_sniffer_arguments {
    char ifc[20];
    int client;
};

void *ping_sniffer(void *arg);
void ping_success(struct ping_callback_arguments *arg, const struct pcap_pkthdr *header, const unsigned char *packet);
void *ping_decoy_sniffer(void *arg);
void ping_decoy_success(bool *ok, const struct pcap_pkthdr *header, const unsigned char *packet);
int ping(struct ping_arguments *ping_arg);
unsigned short checksum(void *b, int len);
void alarm_handler(int sig);