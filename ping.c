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
#include <errno.h>

#define PCKT_LEN 8192

#ifndef FUNCTIONS_H
#include "functions.h"
#endif
#ifndef PING_H
#include "ping.h"
#endif

// NORMALNI PING

void *ping_sniffer(void *arg) {

    struct ping_arguments args = *(struct ping_arguments*)arg;

	pcap_t *sniff;
    char *dev = args.ifc;			/* The device to sniff on */
    char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
    struct bpf_program fprog;		/* The compiled filter */
    char *filter = args.filter;	/* The filter expression */
    bpf_u_int32 mask;		/* Our netmask */
    bpf_u_int32 net;		/* Our IP */
    struct pcap_pkthdr header;	/* The header that pcap gives us */
    const unsigned char *packet;		/* The actual packet */

    if(pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
        net = 0;
        mask = 0;
    }
    sniff = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf); // 1514, 4000
    if(sniff == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        free(arg);
        exit(1);
    }
    /* FILTR NEFUNGUJE VSUDE
    if (pcap_compile(sniff, &fprog, filter, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter, pcap_geterr(sniff));
        free(arg);
        exit(1);
    }
    if (pcap_setfilter(sniff, &fprog) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter, pcap_geterr(sniff));
        free(arg);
        exit(1);
    }*/

    // argumenty co posles do callbacku
    struct ping_callback_arguments *ping_callback_arg = malloc(sizeof(struct ping_callback_arguments));
    if(ping_callback_arg == NULL) {
        fprintf(stderr,"Chyba alokaci pameti.\n");
        exit(1);
    }
    ping_callback_arg->ok = malloc(sizeof(bool*));
    if(ping_callback_arg->ok == NULL) {
        fprintf(stderr,"Chyba alokaci pameti.\n");
        exit(1);
    }
    memset(ping_callback_arg->target,'\0',16);
    memset(ping_callback_arg->ifc,'\0',20);
    memset(ping_callback_arg->ip,'\0',16);
    memset(ping_callback_arg->filter,'\0',100);
    strcpy(ping_callback_arg->target,args.target);
    strcpy(ping_callback_arg->ip,args.ip);
    strcpy(ping_callback_arg->ifc,args.ifc);
    strcpy(ping_callback_arg->filter,args.filter);
    ping_callback_arg->client = args.client;
    ping_callback_arg->ok = args.ok;

    // sem nastav alarm na 2-3 s misto poctu odch paketu
	if (pcap_loop(sniff, 5, (pcap_handler)ping_success, (unsigned char*)ping_callback_arg) < 0) {
    	fprintf(stderr, "cannot get raw packet: %s\n", pcap_geterr(sniff));
        free(arg);
		exit(1);
	}

    pcap_freecode(&fprog);
    pcap_close(sniff);

    free(arg);

    return NULL;
}

void ping_success(struct ping_callback_arguments *arg, const struct pcap_pkthdr *header, const unsigned char *packet) {

    arg = (struct ping_callback_arguments *)arg;
    // kvuli nefungujicim filtrum
    // parsovany paket
    struct iphdr *ip;
    struct tcpheader *tcp;
    ip = (struct iphdr *)(packet + 14);
    if (ip->protocol == 6) {
        tcp = (struct tcpheader *)(packet + 14 + ip->tot_len * 4);

        //unsigned short srcport = ntohs(tcp->tcph_srcport); PORTY SNAD ZATIM NEPOTREBUJU
        //unsigned short dstport = ntohs(tcp->tcph_destport);

        char srcname[16];
        int network_byte_order = htonl(ip->saddr);
        inet_ntop(AF_INET, &network_byte_order, srcname, INET_ADDRSTRLEN);
        char dstname[16];
        int network_byte_order2 = htonl(ip->daddr);
        inet_ntop(AF_INET, &network_byte_order2, dstname, INET_ADDRSTRLEN);

        // pokud target posila zpet reply
        if(!strcmp(dstname,arg->ip) && !strcmp(srcname,arg->target))
            arg->ok = (bool *)true;
    }  
    free(arg);    
    // nastaveni promenne v cyklu interface v main, ze tohle interface je ok a muze se pokracovat
    // ve sberu IP adres z adresy a masky tohohle interface
}

void ping(struct ping_arguments *ping_arg) { // http://www.enderunix.org/docs/en/rawipspoof/

    pthread_t ping_sniffer_thread; // id podrizeneho snifferu

    struct iphdr ip;
    struct icmphdr icmp;
	const int one = 1;
	struct sockaddr_in sin;
	unsigned char *packet;
	packet = (unsigned char *)malloc(60);
	ip.ihl = 5;
	ip.version = 4;
    ip.tos = 0;
    ip.tot_len = htons(60);
    ip.id = htons(12830);
    ip.frag_off = 0;
    ip.ttl = 64;
    ip.protocol = IPPROTO_ICMP;
    ip.saddr = inet_addr(ping_arg->ip);
    ip.daddr = inet_addr(ping_arg->target);
    ip.check = csum((unsigned short *)&ip, sizeof(ip));
    memcpy(packet, &ip, sizeof(ip));
    icmp.type = ICMP_ECHO;
    icmp.code = 0;
    icmp.un.echo.id = 1000;
    icmp.un.echo.sequence = 0;
    icmp.checksum = csum((unsigned short *)&icmp, 8);
    memcpy(packet + 20, &icmp, 8);

    if (setsockopt(ping_arg->client, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        fprintf(stderr,"setsockopt() error.\n");
        exit(1);
    }
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = ip.daddr;

    // vytvor vlakno se snifferem
    if(pthread_create(&ping_sniffer_thread, NULL, ping_sniffer, (void *)ping_arg)) {
        fprintf(stderr,"Chyba pri vytvareni vlakna.\n");
        exit(1);
    }

    // odesli ICMP ping
	if (sendto(ping_arg->client, packet, 60, 0, (struct sockaddr *)&sin, sizeof(struct sockaddr)) < 0)  {
		fprintf(stderr,"Chyba pri odesilani pingu pres socket. R: %s\n",strerror(errno));
		exit(1);
    }

    pthread_join(ping_sniffer_thread, NULL); // pockej na ukonceni ping receiveru

}