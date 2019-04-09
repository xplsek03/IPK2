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

    struct ping_sniffer_arguments args = *(struct ping_sniffer_arguments*)arg;

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
    }/* FILTR NEFUNGUJE VSUDE
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

    printf("interface %s\n",dev);
    printf("filter: %s\n",filter);


    struct ping_succ_arg *ping_success_args = malloc(sizeof(struct ping_succ_arg));
    ping_success_args->myip = args.myip;
    ping_success_args->target = args.target;
    ping_success_args->ok = args.ok;

    // sem nastav alarm na 2-3 s misto poctu odch paketu
	if (pcap_loop(sniff, 5, (pcap_handler)ping_success, (unsigned char*)ping_success_args) < 0) {
    	fprintf(stderr, "cannot get raw packet: %s\n", pcap_geterr(sniff));
        free(arg);
		exit(1);
	}

    pcap_freecode(&fprog);
    pcap_close(sniff);

    free(arg);

    return NULL;
}

void ping_success(struct ping_succ_arg *arg, const struct pcap_pkthdr *header, const unsigned char *packet) {
    
    arg = (struct ping_succ_arg *)arg;
    // kvuli nefungujicim filtrum
    // parsovany paket
    struct iphdr *ip;
    struct tcpheader *tcp;
    ip = (struct iphdr *)(packet + 14);
    if (ip->protocol == 6) {
        tcp = (struct tcpheader *)(packet + 14 + ip->tot_len * 4);

        //unsigned short srcport = ntohs(tcp->tcph_srcport);
        //unsigned short dstport = ntohs(tcp->tcph_destport);

        char srcname[16];
        int network_byte_order = htonl(ip->saddr);
        inet_ntop(AF_INET, &network_byte_order, srcname, INET_ADDRSTRLEN);
        char dstname[16];
        int network_byte_order2 = htonl(ip->daddr);
        inet_ntop(AF_INET, &network_byte_order2, dstname, INET_ADDRSTRLEN);

        // pokud target posila zpet reply
        if(!strcmp(dstname,arg->myip) && !strcmp(srcname,arg->target))
            arg->ok = (bool *)true;
    }  
    free(arg);    
    // nastaveni promenne v cyklu interface v main, ze tohle interface je ok a muze se pokracovat
    // ve sberu IP adres z adresy a masky tohohle interface
}

void ping(int client, char *target, char *myip, bool *ok, char *ifc, char *filter) { // http://www.enderunix.org/docs/en/rawipspoof/

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

    // vytvor argumenty pro ping_sniffer
    struct ping_sniffer_arguments *ping_sniff_arg = malloc(sizeof(struct ping_sniffer_arguments));
    if(ping_sniff_arg == NULL) {
		fprintf(stderr,"Chyba pri alokaci pameti.\n");
		exit(1);        
    }

    ping_sniff_arg->filter = malloc(sizeof(char) * 100);
    memset(ping_sniff_arg->filter,'\0',100);
    ping_sniff_arg->ok = malloc(sizeof(bool));
    ping_sniff_arg->ifc = malloc(sizeof(char) * 20);
    memset(ping_sniff_arg->ifc,'\0',20);
    ping_sniff_arg->filter = filter;
    ping_sniff_arg->client = client;
    ping_sniff_arg->ok = ok;
    ping_sniff_arg->ifc = ifc;
    ping_sniff_arg->myip = myip;
    ping_sniff_arg->target = target;

    printf("z pingu do nej cpu: %s\n",ping_sniff_arg->filter);
    printf("v args je: %s\n",filter);


    // vytvor vlakno se snifferem
    if(pthread_create(&ping_sniffer_thread, NULL, ping_sniffer, (void *)ping_sniff_arg)) {
        fprintf(stderr,"Chyba pri vytvareni vlakna.\n");
        exit(1);
    }

    // odesli ICMP ping
	if (sendto(client, packet, 60, 0, (struct sockaddr *)&sin, sizeof(struct sockaddr)) < 0)  {
		fprintf(stderr,"Chyba pri odesilani pingu pres socket. R: %s\n",strerror(errno));
		exit(1);
    }

    pthread_join(ping_sniffer_thread, NULL); // pockej na ukonceni ping receiveru

}