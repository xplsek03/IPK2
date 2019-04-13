// struktury a CRC, prevzato z https://www.tenouk.com/Module43a.html

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
#include <ctype.h>
#include <netdb.h>
#include <linux/if_link.h>
//#include <net/if_dl.h>
// https://stackoverflow.com/questions/1520649/what-package-do-i-need-to-install-for-using-routing-sockets
#include <sys/time.h>
#include <net/if.h>
#include <sys/ioctl.h>

#define PCKT_LEN 8192

#ifndef FUNCTIONS_H
#include "functions.h"
#endif
#ifndef PING_H
#include "ping.h"
#endif

unsigned short csum(unsigned short *buf, int len) {
    unsigned long sum;
    for(sum=0; len>0; len--)
            sum += *buf++;
    sum = (sum >> 16) + (sum &0xffff);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

// https://www.stev.org/post/clinuxgetmacaddressfrominterface
void *get_mac(char *mac, char *dev) {
    int sock = socket(PF_INET, SOCK_DGRAM, 0);
    struct ifreq req;
    int i = 0;

    if (sock < 0) {
        fprintf(stderr,"Chyba pri zakladani socketu.\n");
        exit(1);
    }

    memset(&req, 0, sizeof(req));
    strncpy(req.ifr_name, dev, IF_NAMESIZE - 1);

    if (ioctl(sock, SIOCGIFHWADDR, &req) < 0) {
        fprintf(stderr,"CIoctl error.\n");
        exit(1);
    }
    snprintf(mac,18,"%.2X:%.2X:%.2X:%.2X:%.2X:%.2X",(unsigned char)req.ifr_hwaddr.sa_data[0],(unsigned char)req.ifr_hwaddr.sa_data[1],(unsigned char) req.ifr_hwaddr.sa_data[2],(unsigned char) req.ifr_hwaddr.sa_data[3],(unsigned char) req.ifr_hwaddr.sa_data[4],(unsigned char) req.ifr_hwaddr.sa_data[5]);
    close(sock);
}

void send_syn(int spoofed_port, int target_port, char *spoofed_address, char *target_address, int client) {

    struct sockaddr_in spoof;
    // obsah paketu
    char buffer[PCKT_LEN];
    memset(buffer, 0, PCKT_LEN);

    // The size of the headers
    struct iphdr *ip = (struct iphdr *) buffer;
    struct tcpheader *tcp = (struct tcpheader *) (buffer + sizeof(struct iphdr));
    struct sockaddr_in sin, din;
    int one = 1;

    // Address family
    sin.sin_family = AF_INET;
    din.sin_family = AF_INET;
    // Source port, can be any, modify as needed
    sin.sin_port = htons(spoofed_port);
    din.sin_port = htons(target_port);
    // Source IP, can be any, modify as needed
    sin.sin_addr.s_addr = inet_addr(spoofed_address);
    din.sin_addr.s_addr = inet_addr(target_address);
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
    ip->daddr = inet_addr(target_address);
    // The TCP structure. The source port, spoofed, we accept through the command line
    tcp->tcph_srcport = htons(spoofed_port);
    // The destination port, we accept through command line
    tcp->tcph_destport = htons(target_port);
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
    if(setsockopt(client, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        fprintf(stderr,"setsockopt() error.\n");
        exit(1);
    }

    if(sendto(client, buffer, ip->tot_len, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
        fprintf(stderr,"Chyba pri odesilani dat pres socket.\n");
        exit(1);
    }
}

int portCount(int type, struct port *arr) {
    // 0 = chyba
    // 1 = jedna pomlcka
    // 2 = nejake carky
    // 3 = jen cisla
    if(type == 1)
        return arr[1].port - arr[0].port + 1;
    else 
        return sizeof(arr)/sizeof(struct port);   
}

// sniffer co zachycuje na konkretnim rozhrani pakety jdouci na jeho konkretni rozhrani
void *interface_sniffer(void *arg) { // tenhle sniffer zajima SYN ACK / RST / nejake ICMP

    struct port_sniffer_arguments args = *(struct port_sniffer_arguments *)arg;

    char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
    bpf_u_int32 mask;		/* Our netmask */
    bpf_u_int32 net;		/* Our IP */
    struct pcap_pkthdr header;	/* The header that pcap gives us */
    const unsigned char *packet;		/* The actual packet */

    if(pcap_lookupnet(args.ifc, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", args.ifc, errbuf);
        net = 0;
        mask = 0;
    }
    pcap_t *ifc_sniff = pcap_open_live(args.ifc, BUFSIZ, 1, 1000, errbuf); // 1514, 4000
    if(ifc_sniff == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", args.ifc, errbuf);
        free(arg);
        exit(1);
    }
    
    int retv;

    //retv = pcap_loop(ifc_sniff, -1, (pcap_handler)interface_success, (unsigned char*)NULL);
    // sem nastav alarm na 2-3 s misto poctu odch paketu
	if (retv == -2) {
        ;
	}
    else if(retv < 0) {
    	fprintf(stderr, "cannot get raw packet: %s\n", pcap_geterr(ifc_sniff));
        free(arg);
		exit(1);
    }

    pcap_close(ifc_sniff);
    //free(arg);
    return NULL;
}

/////////////////////////////

// http://man7.org/linux/man-pages/man3/getifaddrs.3.html pro pokrocile moznosti a ipv6
struct single_interface *getInterface(int *interfaces_count) {

    // vytvor argumenty co pujdou do *interfaces
    struct single_interface *interfaces = malloc(10 * sizeof(struct single_interface)); // pole max. deseti interfaces
    if(interfaces == NULL) {
        fprintf(stderr,"Chyba alokace pameti.\n");
        exit(1);
    }
    struct ifaddrs *ifaddr, *ifa;
    int family, s, n, m;
    char host[16];
    char mask[16];

    if (getifaddrs(&ifaddr) == -1) {
        fprintf(stderr,"Chyba pri getifaddress.\n");
        exit(1);
    }

    for (ifa = ifaddr, n = 0; ifa != NULL; ifa = ifa->ifa_next, n++) {

        if (ifa->ifa_addr == NULL)
            continue;

        family = ifa->ifa_addr->sa_family;

        if (family == AF_INET) {

            //struct sockaddr_ll *hw = (struct sockaddr_ll*)ifa->ifa_addr;
            //for (int i=0; i < hw->sll_halen; i++)
            //   printf("%02x%c", (hw->sll_addr[i]), (i+1!=hw->sll_halen)?':':'\n');

            s = getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in), host, 16, NULL, 0, NI_NUMERICHOST);
            m = getnameinfo(ifa->ifa_netmask, sizeof(struct sockaddr_in), mask, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
            if (s != 0) {
                fprintf(stderr,"Getnameinfo() failed: %s.s\n", gai_strerror(s));
                exit(1);
            }

            if(!strcmp(host, "127.0.0.1")) { // localhosst skip. BUG: dalsi adresy
                continue;
            }

            // napln konkretni rozhrani
            memset(interfaces[*interfaces_count].mask,'\0',16);
            memset(interfaces[*interfaces_count].name,'\0',20);
            memset(interfaces[*interfaces_count].ip,'\0',16);
            strcpy(interfaces[*interfaces_count].mask,mask);
            strcpy(interfaces[*interfaces_count].ip,host);
            strcpy(interfaces[*interfaces_count].name,ifa->ifa_name);
            interfaces[*interfaces_count].usable = false;

            (*interfaces_count)++;
        }
    }

    freeifaddrs(ifaddr);
    return interfaces;
}

// vygeneruj decoy pro jedno konkretni rozhrani
// pocet dalsich pripadnych pouzitych rozhrani osetri post. nahrazovanim v **addresses z funkce main()
void generate_decoy_ips(struct single_interface interface, int *passed_interfaces, struct single_address *addresses, int *decoy_count, int client, char *target, struct sockaddr_in *target_struct) { // https://stackoverflow.com/questions/44295654/print-all-ips-based-on-ip-and-mask-c

    struct in_addr ipaddress, subnetmask;

    inet_pton(AF_INET, interface.ip, &ipaddress);
    inet_pton(AF_INET, interface.mask, &subnetmask);

    unsigned long interface_ip = ntohl(ipaddress.s_addr);
    unsigned long first_ip = ntohl(ipaddress.s_addr & subnetmask.s_addr);
    unsigned long last_ip = ntohl(ipaddress.s_addr | ~(subnetmask.s_addr));

    char decoy[16]; // decoy adresa
    int add_decoy = 0; // lokalni iterator poctu pridavanych decoys z jednoho rozhrani

    // pro kazdou subadresu v siti spust decoy ping test
    for (unsigned long ip = first_ip; ip <= last_ip; ++ip) {

        unsigned long theip = htonl(ip);

        if(add_decoy == (DECOYS / *passed_interfaces)) // uz dosahl plneho pole pro tuto n-tou iteraci
            break;

        if(ip == first_ip || ip == last_ip || ip == interface_ip) // sit ani broadcast nechces
            continue;

        inet_ntop(AF_INET, &theip, decoy, INET_ADDRSTRLEN);
        bool decoy_ping_succ = false; // pokud je adresa pouzivana, vrati true

        // argumenty pro decoy ping
        struct ping_arguments *ping_arg = malloc(sizeof(struct ping_arguments));
        ping_arg->target_struct = malloc(sizeof(struct sockaddr_in *));
        if(ping_arg == NULL) {
            fprintf(stderr,"Chyba pri alokaci pameti.");
            exit(1);
        }

        ping_arg->ok = malloc(sizeof(bool*));
        if(ping_arg->ok == NULL) {
            fprintf(stderr,"Chyba pri alokaci pameti.");
            exit(1);
        }
        if(ping_arg->target_struct == NULL) {
            fprintf(stderr,"Chyba pri alokaci pameti.");
            exit(1);
        }
        memset(ping_arg->target,'\0',16);
        memset(ping_arg->ifc,'\0',20);
        memset(ping_arg->ip,'\0',16);
        strcpy(ping_arg->target,decoy);
        strcpy(ping_arg->ip,interface.ip);
        strcpy(ping_arg->ifc,interface.name);
        ping_arg->client = client;
        ping_arg->ok = &decoy_ping_succ;

        // decoy target override
        struct hostent *hname;
        struct sockaddr_in decoy_target;
        hname = gethostbyname(decoy);
        memset(&decoy_target, '\0', sizeof(decoy_target));
        decoy_target.sin_family = hname->h_addrtype;
        decoy_target.sin_port = 0;
        decoy_target.sin_addr.s_addr = *(long*)hname->h_addr_list[0];

        ping_arg->target_struct = &decoy_target;

        ping(ping_arg);

        free(ping_arg);

        if(decoy_ping_succ) { // pingovana adresa je pouzivana, pokracuj
            decoy_ping_succ = false;
        }
        else { // pridej adresu do pole addresses a dokud jich neni %DECOYS, pokracuj
            if(add_decoy < (DECOYS / *passed_interfaces)) {
                memset(addresses[add_decoy].ip,'\0',16);
                strcpy(addresses[add_decoy].ip,decoy);
                memset(addresses[add_decoy].ifc,'\0',20);
                strcpy(addresses[add_decoy].ifc,interface.name);
                add_decoy++; // lokalni iterator
                *decoy_count = *decoy_count + 1; // globalni iterator decoy adres
            }
        }

    }
}

int rndm(int lower, int upper) { 
    return (rand() % (upper - lower + 1)) + lower;
}

// to co ridi jedno cele rozhrani
void *interface_looper(void* arg) {

    pthread_t port_sniff;
    struct interface_arguments args = *(struct interface_arguments*)arg;

    // lokalni interface seznam portu ke zpracovani
    struct port local_list[args.pt_arr_size];

    // vytvor argumenty port snifferu
    struct port_sniffer_arguments *port_sniff_arg = malloc(sizeof(struct port_sniffer_arguments));
        if(port_sniff_arg == NULL) {
            fprintf(stderr,"Chyba pri alokaci pameti.\n");
            exit(1);        
        }
        memset(port_sniff_arg->ifc,'\0',20);
        strcpy(port_sniff_arg->ifc,args.ifc);
        port_sniff_arg->client = args.client;

    // vytvor port sniffer a nahraj do nej argumenty
    if (pthread_create(&port_sniff, NULL, interface_sniffer, (void *)port_sniff_arg)) {
        fprintf(stderr, "Chyba pri vytvareni vlakna.\n");
        exit(1);
    }

    // spocitej kolik domen je v tomto interface
    int domain_counter = 0;
    for(int i = 0; i < args.decoy_count; i++) {
        if(!strcmp(args.addresses[i].ifc,args.ifc)) {
            domain_counter++;
        }
    }

    // vytvor vlakna z decoy domen, pocet domen v interface
    pthread_t domain[domain_counter];
    void *retval[domain_counter];
    int c = 0; // vnitrni pocitadlo generatoru vlaken

    for(int i = 0; i < args.decoy_count; i++) {
        if(!strcmp(args.addresses[i].ifc,args.ifc)) {
            struct domain_arguments *domain_arg = malloc(sizeof(struct domain_arguments));
            domain_arg->local_list = malloc(args.pt_arr_size * sizeof(struct port *));
            if(domain_arg->local_list == NULL) {
                fprintf(stderr,"Chyba pri alokaci pameti.\n");
                exit(1);        
            }            
            domain_arg->global_queue = malloc(sizeof(struct queue *));
            domain_arg->global_queue->q = malloc(args.pt_arr_size * sizeof(struct port *));
            if(domain_arg == NULL) {
                fprintf(stderr,"Chyba pri alokaci pameti.\n");
                exit(1);        
            }
            if(domain_arg->global_queue == NULL) {
                fprintf(stderr,"Chyba pri alokaci pameti.\n");
                exit(1);        
            }
            if(domain_arg->global_queue->q == NULL) {
                fprintf(stderr,"Chyba pri alokaci pameti.\n");
                exit(1);        
            }

            domain_arg->global_queue = args.global_queue;
            domain_arg->global_queue->q = args.global_queue->q;
            domain_arg->local_list = local_list;
            domain_arg->client = args.client;
            memset(domain_arg->target_address,'\0',16);
            strcpy(domain_arg->target_address,args.target_address);
            domain_arg->pt_arr_size = args.pt_arr_size;
            memset(domain_arg->ip,'\0',16);
            strcpy(domain_arg->ip,args.addresses[i].ip);
            
            pthread_create(&domain[c++], NULL, domain_loop, (void *)domain_arg);
        }
    }

    // pockej na zbytek deti
    for(int i = 0; i < domain_counter; i++)
        pthread_join(domain[i], &retval[i]);

    // pockej na port sniffer
    pthread_join(port_sniff, NULL);
    free(port_sniff_arg);
    return NULL;
} 

// to co posila SYNy z konkretni domeny
void *domain_loop(void *arg) {

    // rozbal argumenty
    struct domain_arguments args = *(struct domain_arguments*)arg;

    

    // spoofed port ze kteryho odesles SYN
    int spoofed_port = rndm(PORT_RANGE_START, PORT_RANGE_END);

    // projed max pocet portu - mutex - zabrani aby jely vickrat
    //for(int i = 0; i < args.pt_arr_size; i++) { // BUG: pri udp pridat pu_arr_size
    //    send_syn(spoofed_port, args.pt_arr[i], args.ip, args.target_address, args.client);
    //}
}

void randomize(struct port *array, int n) {
    if (n > 1) {
        size_t i;
        for (i = 0; i < n - 1; i++) {
            size_t j = i + rand() / (RAND_MAX / (n - i) + 1);
            struct port t = array[j];
            array[j] = array[i];
            array[i] = t;
        }
    }
}

// ARGUMENT PARSING: FUNKCE

int checkArg(char *argument) {

    int range = 0; // -
    int col = 0; // ,
    for(int i = 0; i < strlen(argument); i++) {
        if(isdigit(argument[i])) {
            continue;
        }
        else if(argument[i] == '-') {
            range++;
        }
        else if(argument[i] == ',')
            col++;
        else
            return 0;       
    } 
    if(range > 1 || !isdigit(argument[strlen(argument)-1]) || (range > 0 && col > 0)) {
        return 0;
    }
    
    if(range == 1) {
		return 1; // je tam jedna pomlcka		
	}
	else if(col > 1)
		return 2; // jsou tam carky
	else
		return 3; // jsou tam jen cisla
}

int getCharCount(char *str, char z) {
    int c = 0;
    for(int i = 0; i < strlen(str); i++) {
        if(str[i] == z)
            c++;
    }
    return c;
}

// PORT QUEUE

struct port queue_peek(struct port *q, int front) { // nepouzivat
    return q[front];
}

bool queue_isEmpty(int count) {
    return count == 0;
}

bool queue_isFull(int count, int max) { // prebytecne, k preplneni nedojde
    return count == max;
}

int queue_size(int count) { // dat mutex
    return count;
}  

void queue_insert(struct port data, int rear, int max, struct port *q, int count) {
    if(!queue_isFull(count, max)) {
	    if(rear == max-1) {
            rear = -1;            
        }       
        q[++rear] = data;
        count++;
    }
}

struct port queue_removeData(struct port *q, int front, int max, int count) { // dat mutex
    struct port data = q[front++];
	if(front == max) {
        front = 0;
    }
	count--;
    return data;  
}