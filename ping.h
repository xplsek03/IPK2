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

#define PCKT_LEN 8192

#ifndef FUNCTIONS_H
#include "functions.h"
#endif

void *ping_sniffer(void *arg);
void ping_success(bool *ok, const struct pcap_pkthdr *header, const unsigned char *packet);
void *ping(void *arg);
