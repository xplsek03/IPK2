#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h> // sleep()
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
    char *ip;
    char *target;
    int client;
    bool *ok;
    char *ifc;
    char *filter;
};

struct ping_sniffer_arguments {
    char *ifc;
    char *filter;
    int client;
    bool *ok;
    char *myip;
    char *target;
};

struct port_sniffer_arguments {
    char *ifc;
    char *filter;
    int client;
};

struct ping_succ_arg {
    char *myip;
    char *target;
    bool *ok;
};

void *ping_sniffer(void *arg);
void ping_success(struct ping_succ_arg *arg, const struct pcap_pkthdr *header, const unsigned char *packet);
void *ping_decoy_sniffer(void *arg);
void ping_decoy_success(bool *ok, const struct pcap_pkthdr *header, const unsigned char *packet);
void ping(int client, char *target, char *ip, bool *ok, char *ifc, char *filter);
