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
#include <netinet/ip_icmp.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <ifaddrs.h>

#define PCKT_LEN 8192

#include "functions.h"

unsigned short csum(unsigned short *buf, int len) {
    unsigned long sum;
    for(sum=0; len>0; len--)
            sum += *buf++;
    sum = (sum >> 16) + (sum &0xffff);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

void* send_syn(void *arg) {

    struct thread_arguments args = *(struct thread_arguments*)arg;

    struct sockaddr_in spoof;
    // obsah paketu
    char buffer[PCKT_LEN];
    memset(buffer, 0, PCKT_LEN);

    // The size of the headers
    struct iphdr *ip = (struct iphdr *) buffer;
    struct tcpheader *tcp = (struct tcpheader *) (buffer + sizeof(struct iphdr));
    struct sockaddr_in sin, din;
    int one = 1;

    // generate random address
    char *spoofed_address = args.addresses[rand()%args.address_count];
    // Address family
    sin.sin_family = AF_INET;
    din.sin_family = AF_INET;
    // Source port, can be any, modify as needed
    sin.sin_port = htons(args.spoofed_port);
    din.sin_port = htons(args.target_port);
    // Source IP, can be any, modify as needed
    sin.sin_addr.s_addr = inet_addr(spoofed_address);
    din.sin_addr.s_addr = inet_addr(args.target_address);
    // IP structure
    ip->ihl = 5; // 4 ?
    ip->version = 4;
    ip->tos = 16;
    ip->tot_len = sizeof(struct iphdr) + sizeof(struct tcpheader);
    ip->id = htons(13375);
    ip->frag_off = 0;
    ip->ttl = 64;
    ip->protocol = 6; // TCP
    ip->check = 0; // Done by kernel
    ip->saddr = inet_addr(spoofed_address);
    ip->daddr = inet_addr(args.target_address);
    // The TCP structure. The source port, spoofed, we accept through the command line
    tcp->tcph_srcport = htons(args.spoofed_port);
    // The destination port, we accept through command line
    tcp->tcph_destport = htons(args.target_port);
    tcp->tcph_seqnum = htonl(1);
    tcp->tcph_acknum = 0;
    tcp->tcph_offset = 5;
    tcp->tcph_syn = 1;
    tcp->tcph_ack = 0; // ? non zero?
    tcp->tcph_win = htons(32767);
    tcp->tcph_chksum = 0; // Done by kernel
    tcp->tcph_urgptr = 0;
    // IP checksum calculation
    ip->check = csum((unsigned short *) buffer, (sizeof(struct iphdr) + sizeof(struct tcpheader)));

    // Inform the kernel do not fill up the headers' structure, we fabricated our own
    if(setsockopt(args.client, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        fprintf(stderr,"setsockopt() error.\n");
        exit(1);
    }

    if(sendto(args.client, buffer, ip->tot_len, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
        fprintf(stderr,"Chyba pri odesilani dat pres socket.\n");
        exit(1);
    }
    free(arg);
    arg = NULL; // mozna BUG
    return NULL;
}

int portCount(int type, int *arr) {
    // 0 = chyba
    // 1 = jedna pomlcka
    // 2 = nejake carky
    // 3 = jen cisla
    if(type == 1)
        return arr[1] - arr[0]+1;
    else 
        return sizeof(arr)/sizeof(int);   
}

void *sniffer(void *arg, char *ifc) {
	pcap_t *sniff;
	char *filter = "dst host 172.17.14.90 and ip"; // nastav vyhledavaci frazi na 
	char *dev = ifc;
	char errbuf[PCAP_ERRBUF_SIZE];
	bpf_u_int32	netp;
	bpf_u_int32	maskp;
	struct bpf_program fprog;
	int dl = 0, dl_len = 0;

	if ((sniff = pcap_open_live(dev, 1514, 1, 500, errbuf)) == NULL) {
		fprintf(stderr, "cannot open device %s: %s\n", dev, errbuf);
		exit(1);
	}

	pcap_lookupnet(dev, &netp, &maskp, errbuf);
	pcap_compile(sniff, &fprog, filter, 0, netp);
	if (pcap_setfilter(sniff, &fprog) == -1) {
		fprintf(stderr, "cannot set pcap filter %s: %s\n", filter, errbuf);
		exit(1);
	}
	pcap_freecode(&fprog);
	dl = pcap_datalink(sniff);
	
	switch(dl) {
		case 1:
			dl_len = 14;
			break;
		default:
			dl_len = 14;
			break;
	}

	//if (pcap_loop(sniff, -1, raw_packet_receiver, (u_char *)dl_len) < 0) {
	//	fprintf(stderr, "cannot get raw packet: %s\n", pcap_geterr(pd));
	//	exit(1);
	//}

    return NULL;

}

struct single_interface **getInterface(int *interfaces_count) { // https://stackoverflow.com/questions/18100761/obtaining-subnetmask-in-c
    struct ifaddrs *ifap, *ifa;
    struct sockaddr_in *smask, *sip;
    char *mask, *ip;
    struct single_interface **interfaces = malloc(10 * sizeof(struct single_interface)); // pole max. deseti interfaces
    if(interfaces == NULL) {
        fprintf(stderr,"Chyba alokace pameti.\n");
        exit(1);
    }
    getifaddrs (&ifap);
    for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr->sa_family==AF_INET) {
            smask = (struct sockaddr_in *) ifa->ifa_netmask;
            sip = (struct sockaddr_in *) ifa->ifa_addr;
            mask = inet_ntoa(smask->sin_addr);
            ip = inet_ntoa(sip->sin_addr);
            interfaces[*interfaces_count]->mask = mask;
            interfaces[*interfaces_count]->ip = ip;
            interfaces[*interfaces_count]->name = ifa->ifa_name;
            interfaces_count++;
        }
    }
    freeifaddrs(ifap);
    return interfaces;
}

void ping(int client, char *target, char *myip) { // http://www.enderunix.org/docs/en/rawipspoof/
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
    ip.saddr = inet_addr(myip);
    ip.daddr = inet_addr(target);
    ip.check = csum((unsigned short *)&ip, sizeof(ip));
    memcpy(packet, &ip, sizeof(ip));
    icmp.type = ICMP_ECHO;
    icmp.code = 0;
    icmp.un.echo.id = 1000;
    icmp.un.echo.sequence = 0;
    icmp.checksum = csum((unsigned short *)&icmp, 8);
    memcpy(packet + 20, &icmp, 8);

    if (setsockopt(client, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        fprintf(stderr,"setsockopt() error.\n");
        exit(1);
    }
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = ip.daddr;

	if (sendto(client, packet, 60, 0, (struct sockaddr *)&sin, sizeof(struct sockaddr)) < 0)  {
		fprintf(stderr,"Chyba pri odesilani pingu pres socket.\n");
		exit(1);
	}
}
