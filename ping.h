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

struct ping_arguments {
    char ip[16];
    char target[16];
    int client;
    bool *ok;
    char ifc[20];
    char filter[100];
};

struct ping_callback_arguments {
    char ip[16];
    char target[16];
    int client;
    bool *ok;
    char ifc[20];
    char filter[100];
};

struct port_sniffer_arguments {
    char ifc[20];
    char filter[100];
    int client;
};

void *ping_sniffer(void *arg);
void ping_success(struct ping_callback_arguments *arg, const struct pcap_pkthdr *header, const unsigned char *packet);
void *ping_decoy_sniffer(void *arg);
void ping_decoy_success(bool *ok, const struct pcap_pkthdr *header, const unsigned char *packet);
void ping(struct ping_arguments *ping_arg);
