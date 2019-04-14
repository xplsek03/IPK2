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
#include <netdb.h>
#include <signal.h>

#ifndef FUNCTIONS_H
#include "functions.h"
#endif
#ifndef PING_H
#include "ping.h"
#endif

/*********************************************************************************************
 *     
 * globalni dniffer na ping, je tu kvuli sigalarm zastaveni
 *
 *********************************************************************************************/
pcap_t *sniff; // globalni sniffer na ping

/*********************************************************************************************
 *     
 * alarm, v pripade necinnosti zastavi ping sniffer (hledani volnych domen)
 *
 *********************************************************************************************/
void alarm_handler(int sig) {
    pcap_breakloop(sniff);
}

/*********************************************************************************************
 *     
 * checksum funkce 2
 *
 *********************************************************************************************/
unsigned short checksum(void *b, int len) {
    unsigned short *buf = b;
	unsigned int sum=0;
	unsigned short result;
	for ( sum = 0; len > 1; len -= 2 )
		sum += *buf++;
	if ( len == 1 )
		sum += *(unsigned char*)buf;
	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);
	result = ~sum;
	return result;
}

/*********************************************************************************************
 *     
 * sniffer na ping
 *
 *********************************************************************************************/
void *ping_sniffer(void *arg) {

    struct ping_arguments args = *(struct ping_arguments*)arg;

	char *dev = args.ifc;			/* The device to sniff on */
    char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
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

    // argumenty co posles do callbacku
    struct ping_callback_arguments *ping_callback_arg = malloc(sizeof(struct ping_callback_arguments));
    if(ping_callback_arg == NULL) {
        fprintf(stderr,"Chyba alokaci pameti.\n");
        exit(1);
    }  
    ping_callback_arg->sniff = malloc(sizeof(pcap_t *));
    if(ping_callback_arg->sniff == NULL) {
        fprintf(stderr,"Chyba alokaci pameti.\n");
        exit(1);
    }
    memset(ping_callback_arg->target,'\0',16);
    memset(ping_callback_arg->ip,'\0',16);
    strcpy(ping_callback_arg->target,args.target);
    strcpy(ping_callback_arg->ip,args.ip);
    ping_callback_arg->sniff = sniff;

    int retv;

    // v pripade z eodpoved enchce prijit, skonci po 2s
    alarm(2);
    signal(SIGALRM, alarm_handler);

    retv = pcap_loop(sniff, -1, (pcap_handler)ping_callback, (unsigned char*)ping_callback_arg);
    // z callbacku byl zavolan breakloop
	if (retv == -2) {
        args.ok = (bool *)true;
	}
    else if(retv < 0) {
    	fprintf(stderr, "cannot get raw packet: %s\n", pcap_geterr(sniff));
        free(arg);
		exit(1);
    }

    pcap_close(sniff);
    //free(arg);
    return NULL;
}

/*********************************************************************************************
 *     
 * callback ping snifferu
 *
 *********************************************************************************************/
void ping_callback(struct ping_callback_arguments *arg, const struct pcap_pkthdr *header, const unsigned char *packet) {

    arg = (struct ping_callback_arguments *)arg;

    struct iphdr *ip;
    struct tcpheader *tcp;
    ip = (struct iphdr *)(packet + 14);

    if (ip->protocol == 1) {
        tcp = (struct tcpheader *)(packet + 14 + ip->tot_len * 4);

        //unsigned short srcport = ntohs(tcp->tcph_srcport); PORTY SNAD ZATIM NEPOTREBUJU
        //unsigned short dstport = ntohs(tcp->tcph_destport);

        char srcname[16];
        inet_ntop(AF_INET, &ip->saddr, srcname, INET_ADDRSTRLEN);
        char dstname[16];
        inet_ntop(AF_INET, &ip->daddr, dstname, INET_ADDRSTRLEN);

        // nasels ping reply, skonci
        if(!strcmp(dstname,arg->ip) && !strcmp(srcname,arg->target)) {
            pcap_breakloop(arg->sniff);
        }
    }

    // nastaveni promenne v cyklu interface v main, ze tohle interface je ok a muze se pokracovat
    // ve sberu IP adres z adresy a masky tohohle interface
}

/*********************************************************************************************
 *     
 * rizeni jednoho pingu
 * https://www.cs.utah.edu/~swalton/listings/sockets/programs/part4/chap18/myping.c
 *
 *********************************************************************************************/
int ping(struct ping_arguments *ping_arg) {

    pthread_t ping_sniffer_thread; // id podrizeneho snifferu

    // vytvor vlakno se snifferem
    if(pthread_create(&ping_sniffer_thread, NULL, ping_sniffer, (void *)ping_arg)) {
        fprintf(stderr,"Chyba pri vytvareni vlakna.\n");
        exit(1);
    }

    const int val=255;
	int i, cnt=1;
	struct packet pckt;

	int icmp_socket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (icmp_socket < 0) {
        fprintf(stderr,"Chyba pri vytvareni socketu.\n");
		exit(1);
	}
	if (setsockopt(icmp_socket, SOL_IP, IP_TTL, &val, sizeof(val))) {
        fprintf(stderr,"Chyba setsockopt pri nastavovani TTL.\n");
		exit(1);
    }

    memset(&pckt,'\0',sizeof(pckt));

    pckt.hdr.type = ICMP_ECHO;
    for (i = 0; i < sizeof(pckt.msg)-1; i++)
        pckt.msg[i] = i+'0';
    pckt.msg[i] = 0;
    pckt.hdr.un.echo.sequence = cnt++;
    pckt.hdr.checksum = checksum(&pckt, sizeof(pckt));

    for(int i = 0; i < 5; i++) { // 5 odeslani pingu za sebou s intvl=1s
        sleep(1); // pockej chvili na receiver
        if (sendto(icmp_socket, &pckt, sizeof(pckt), 0, (struct sockaddr*)ping_arg->target_struct, sizeof(*ping_arg->target_struct)) < 0) {
            fprintf(stderr,"Chyba pri odesilani pingu pres socket. R: %s\n",strerror(errno));
            exit(1);
        }
        if(ping_arg->ok)
            break;
    }

    pthread_join(ping_sniffer_thread, NULL); // pockej na ukonceni ping receiveru

    if(ping_arg->ok)
        return 1;
    else
        return 0;

}