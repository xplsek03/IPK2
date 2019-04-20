#include <errno.h>
#include <pcap.h>
#include <stdbool.h>
#include <signal.h>

#ifndef SETTINGS_H
#include "settings.h"
#endif
#ifndef FUNCTIONS_H
#include "functions.h"
#endif
#ifndef PING_H
#include "ping.h"
#endif

/*********************************************************************************************
 *     
 * alarm, v pripade necinnosti zastavi ping sniffer (hledani volnych domen)
 * @sig = id signalu
 *
 *********************************************************************************************/
void alarm_handler(int sig) {
    if(alarm_signal)
        pcap_breakloop(sniff);
}

/*********************************************************************************************
 *     
 * ping sniffer
 * pcap sniffer, ktery se spusti na konkretnim rozhrani. Pouze pro ping
 *
 *********************************************************************************************/
void *ping_sniffer(void *arg) {

    struct ping_arguments args = *(struct ping_arguments*)arg;
    alarm_signal = true;

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
        exit(1);
    }

    // v pripade ze odpoved enchce prijit, skonci po 4s
    alarm(4);
    signal(SIGALRM, alarm_handler);

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

    retv = pcap_loop(sniff, -1, (pcap_handler)ping_callback, (unsigned char*)ping_callback_arg);
    // z callbacku byl zavolan breakloop
	if (!alarm_signal && retv == -2) {
        alarm_signal = false;
	}
    else if(!alarm_signal && retv < 0) {
    	fprintf(stderr, "cannot get raw packet: %s\n", pcap_geterr(sniff));
		exit(1);
    }

    alarm_signal = true;

    return NULL;
}

/*********************************************************************************************
 *     
 * callback ping snifferu - pouze pro ping
 *
 *********************************************************************************************/
void ping_callback(struct ping_callback_arguments *arg, const struct pcap_pkthdr *header, const unsigned char *packet) {

    arg = (struct ping_callback_arguments *)arg;

    struct iphdr *ip;
    struct tcpheader *tcp;
    ip = (struct iphdr *)(packet + 14);

    if (ip->protocol == 1) {
        tcp = (struct tcpheader *)(packet + 14 + ip->tot_len * 4);
        char srcname[16];
        inet_ntop(AF_INET, &ip->saddr, srcname, INET_ADDRSTRLEN);
        char dstname[16];
        inet_ntop(AF_INET, &ip->daddr, dstname, INET_ADDRSTRLEN);

        // nasels ping reply, skonci. pridej adresu do fake_ips
        if(!strcmp(dstname,arg->ip) && !strcmp(srcname,arg->target)) {
            decoy_ping_succ = true;
            pcap_breakloop(arg->sniff);
        }
    }

    // nastaveni promenne v cyklu interface v main, ze tohle interface je ok a muze se pokracovat
    // ve sberu IP adres z adresy a masky tohohle interface
}

/*********************************************************************************************
 *     
 * rizeni jednoho konkretniho pingu
 * https://www.cs.utah.edu/~swalton/listings/sockets/programs/part4/chap18/myping.c
 * ret: 0 pri neuspechu, 1 pri uspesnem pingu
 *
 *********************************************************************************************/
int ping(struct ping_arguments *ping_arg) {

    pthread_t ping_sniffer_thread; // id podrizeneho snifferu

    // vytvor vlakno se snifferem
    if(pthread_create(&ping_sniffer_thread, NULL, ping_sniffer, (void *)ping_arg)) {
        fprintf(stderr,"Chyba pri vytvareni vlakna.\n");
        exit(1);
    }

    const int val = 255;
	int i;
    int cnt = 1;
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
    pckt.hdr.checksum = csum((unsigned short *)&pckt, sizeof(pckt));

    for(int i = 0; i < 3; i++) { // 3 odeslani pingu za sebou s intervalem 1s
        usleep(1);
        if (sendto(icmp_socket, &pckt, sizeof(pckt), 0, (struct sockaddr*)ping_arg->target_struct, sizeof(*ping_arg->target_struct)) < 0) {
            fprintf(stderr,"Chyba pri odesilani pingu pres socket. R: %s\n",strerror(errno));
            exit(1);
        }
        if(ping_arg->ok)
            break;
    }
    pthread_join(ping_sniffer_thread, NULL); // pockej na ukonceni ping receiveru

    if(ping_arg->ok) {
        return 1;
    }
    else {
        return 0;
    }
}