#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <string.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <stdbool.h>

#include "settings.h"

struct packet
{
	struct icmphdr hdr;
	char msg[PACKETSIZE-sizeof(struct icmphdr)];
};

struct ping_arguments {
    char ip[16];
    char target[16];
    struct sockaddr_in *target_struct;
    bool *ok;
    char ifc[20];
};

struct ping_callback_arguments {
    char ip[16];
    char target[16];
    pcap_t *sniff;
};

void *ping_sniffer(void *arg);
void ping_callback(struct ping_callback_arguments *arg, const struct pcap_pkthdr *header, const unsigned char *packet);
int ping(struct ping_arguments *ping_arg);
void alarm_handler(int sig);