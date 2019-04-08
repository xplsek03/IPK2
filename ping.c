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
#ifndef PING_H
#include "ping.h"
#endif

// NORMALNI PING

void *ping_sniffer(void *arg) {
    struct ping_sniffer_arguments args = *(struct ping_sniffer_arguments*)arg;
	pcap_t *sniff;
	char *filter = args.filter; // nastav vyhledavaci frazi na ping co jde zpet
	char *dev = args.ifc;
	char errbuf[PCAP_ERRBUF_SIZE];
	bpf_u_int32	netp;
	bpf_u_int32	maskp;
	struct bpf_program fprog;
	int dl = 0, dl_len = 0;
	if ((sniff = pcap_open_live(dev, 1514, 1, 4000, errbuf)) == NULL) { // cekej 4 sekundy a pak shod ping sniffer
		fprintf(stderr, "cannot open device %s: %s\n", dev, errbuf);
		exit(1);
	}
	pcap_lookupnet(dev, &netp, &maskp, errbuf);
	pcap_compile(sniff, &fprog, filter, 0, netp);
	if (pcap_setfilter(sniff, &fprog) == -1) {
		fprintf(stderr, "cannot set pcap filter %s: %s\n", filter, errbuf);
        free(arg);
		exit(1);
	}
	pcap_freecode(&fprog);
	dl = pcap_datalink(sniff);
	if (pcap_loop(sniff, 1, (pcap_handler)ping_success, (unsigned char*)args.ok) < 0) {
		fprintf(stderr, "cannot get raw packet: %s\n", pcap_geterr(sniff));
        free(arg);
		exit(1);
	}
    free(arg);
    return NULL;
}

void ping_success(bool *ok, const struct pcap_pkthdr *header, const unsigned char *packet) {
    *ok = (bool*)true;
    // nastaveni promenne v cyklu interface v main, ze tohle interface je ok a muze se pokracovat
    // ve sberu IP adres z adresy a masky tohohle interface
}

void *ping(void *arg) { // http://www.enderunix.org/docs/en/rawipspoof/

    pthread_t ping_sniffer_thread; // id podrizeneho snifferu

    struct ping_arguments args = *(struct ping_arguments*)arg;
    struct iphdr ip;
    struct icmphdr icmp;
	const int one = 1;
	struct sockaddr_in sin;
	unsigned char *packet;
	packet = (unsigned char *)malloc(60);
	ip.ihl = 0x5;
	ip.version = 0x4;
    ip.tos = 0x0;
    ip.tot_len = htons(60);
    ip.id = htons(12830);
    ip.frag_off = 0x0;
    ip.ttl = 64;
    ip.protocol = IPPROTO_ICMP;
    ip.saddr = inet_addr(args.ip);
    ip.daddr = inet_addr(args.target);
    ip.check = csum((unsigned short *)&ip, sizeof(ip));
    memcpy(packet, &ip, sizeof(ip));
    icmp.type = ICMP_ECHO;
    icmp.code = 0;
    icmp.un.echo.id = 1000;
    icmp.un.echo.sequence = 0;
    icmp.checksum = csum((unsigned short *)&icmp, 8);
    memcpy(packet + 20, &icmp, 8);

    if (setsockopt(args.client, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        fprintf(stderr,"setsockopt() error.\n");
        free(arg);
        exit(1);
    }
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = ip.daddr;

    // vytvor argumenty pro ping_sniffer
    struct ping_sniffer_arguments *ping_sniff_arg = malloc(sizeof(struct ping_sniffer_arguments));
    if(ping_sniff_arg == NULL) {
		fprintf(stderr,"Chyba pri alokaci pameti.\n");
        free(arg);
		exit(1);        
    }

    ping_sniff_arg->filter = args.filter;
    ping_sniff_arg->client = args.client;
    ping_sniff_arg->ok = args.ok; // snad to ok preda pomoci odkazu..
    ping_sniff_arg->ifc = args.ifc;


    // vytvor vlakno se snifferem
    if(pthread_create(&ping_sniffer_thread, NULL, ping_sniffer, &ping_sniff_arg)) {
        fprintf(stderr,"Chyba pri vytvareni vlakna.\n");
        exit(1);
    }

    // odesli ICMP ping
	if (sendto(args.client, packet, 60, 0, (struct sockaddr *)&sin, sizeof(struct sockaddr)) < 0)  {
		fprintf(stderr,"Chyba pri odesilani pingu pres socket.\n");
        free(arg);
		exit(1);
	}

    pthread_join(ping_sniffer_thread, NULL); // pockej na ukonceni ping receiveru
    free(arg);
    return NULL;
}