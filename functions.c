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
#include <netinet/ether.h>
#include <netinet/ip_icmp.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <ifaddrs.h>
#include <ctype.h>
#include <netdb.h>
#include <linux/if_link.h>
#include <sys/time.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <limits.h>
#include <stdbool.h>

#define SLEEP_TIME 7 // spaci cas mezi jednotlivymi prujezdy handleru na lokalnim seznam portu v interface

#ifndef FUNCTIONS_H
#include "functions.h"
#endif
#ifndef PING_H
#include "ping.h"
#endif

// mutexy pro globalni frontu portu
extern pthread_mutex_t mutex_queue_size;
extern pthread_mutex_t mutex_queue_remove;
extern pthread_mutex_t mutex_queue_insert;
// globalni fronta portu
extern struct queue *global_queue;

extern bool decoy_ping_succ;

/*********************************************************************************************
 *     
 *   checksum
 *
 *********************************************************************************************/
unsigned short csum(unsigned short *ptr,int nbytes) {
    long sum;
    unsigned short oddbyte;
    short answer;

    sum=0;
    while(nbytes>1) {
        sum+=*ptr++;
        nbytes-=2;
    }
    if(nbytes==1) {
        oddbyte=0;
        *((u_char*)&oddbyte)=*(u_char*)ptr;
        sum+=oddbyte;
    }

    sum = (sum>>16)+(sum & 0xffff);
    sum = sum + (sum>>16);
    answer=(short)~sum;

    return(answer);
}

/*********************************************************************************************
 *     
 *   ziskej mac adresu // https://www.stev.org/post/clinuxgetmacaddressfrominterface
 *
 *********************************************************************************************/
void *get_mac(char *mac, char *dev) {
    int sock = socket(PF_INET, SOCK_DGRAM, 0);
    struct ifreq req;
    int i = 0;

    if (sock < 0)
    {
        fprintf(stderr, "Chyba pri zakladani socketu.\n");
        exit(1);
    }

    memset(&req, 0, sizeof(req));
    strncpy(req.ifr_name, dev, IF_NAMESIZE - 1);

    if (ioctl(sock, SIOCGIFHWADDR, &req) < 0)
    {
        fprintf(stderr, "CIoctl error.\n");
        exit(1);
    }
    snprintf(mac, 18, "%.2X:%.2X:%.2X:%.2X:%.2X:%.2X", (unsigned char)req.ifr_hwaddr.sa_data[0], (unsigned char)req.ifr_hwaddr.sa_data[1], (unsigned char)req.ifr_hwaddr.sa_data[2], (unsigned char)req.ifr_hwaddr.sa_data[3], (unsigned char)req.ifr_hwaddr.sa_data[4], (unsigned char)req.ifr_hwaddr.sa_data[5]);
    close(sock);
}

/*********************************************************************************************
 *     
 *   odeslani syn paketu z jedne domeny konkretniho interface
 *
 *********************************************************************************************/
void send_syn(int spoofed_port, int target_port, char *spoofed_address, char *target_address, int client) {

    //Data to be appended at the end of the tcp header
    char *data;
    char data_rand[40] = "Z toho stringu se generuji nahodna data";
    data_rand[rndmstr(0,39)] = '\0';
    
    //Ethernet header + IP header + TCP header + data
    char packet[PCKT_LEN];
    //Pseudo TCP header to calculate the TCP header's checksum
    struct pseudoTCPPacket pTCPPacket;
    //Pseudo TCP Header + TCP Header + data
    char *pseudo_packet;
    struct sockaddr_in din;
    din.sin_family = AF_INET;
    din.sin_port = htons(target_port);
    din.sin_addr.s_addr = inet_addr(target_address);

    int one = 1;
    if (setsockopt(client, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        fprintf(stderr, "setsockopt() error.\n");
        exit(1);
    }

    //Allocate mem for ip and tcp headers and zero the allocation
    memset(packet, 0, sizeof(packet));
    struct iphdr *ip = (struct iphdr *) packet;
    struct tcphdr *tcp = (struct tcphdr *) (packet + sizeof(struct iphdr));
    data = (char *)(packet + sizeof(struct iphdr) + sizeof(struct tcphdr));
    strcpy(data,data_rand);

    ip->ihl = 5;
    ip->version = 4;
    ip->tos = 0;
    ip->tot_len = sizeof (struct iphdr) + sizeof (struct tcphdr) + strlen(data);    /* no payload */
    ip->id = htons(54321);   /* the value doesn't matter here */
    ip->frag_off = 0x00;
    ip->ttl = 0xFF;
    ip->protocol = IPPROTO_TCP; //TCP protocol
    ip->check = 0;      /* set it to 0 before computing the actual checksum later */
    ip->saddr = inet_addr(spoofed_address);/* SYN's can be blindly spoofed */
    ip->daddr = inet_addr(target_address);
    //Now we can calculate the check sum for the IP header check field
    ip->check = csum((unsigned short *) packet, ip->tot_len);

    tcp->source = htons(spoofed_port);
    tcp->dest = htons(target_port);
    tcp->seq = rndmsleep(1,ULONG_MAX); // 0x0. nahodna hodnota sekvence
    tcp->ack_seq = 0x0;/* number, and the ack sequence is 0 in the 1st packet */
    tcp->doff = 5; //4 bits: 5 x 32-bit words on tcp header
    tcp->res1 = 0; //4 bits: Not used
    tcp->urg = 0; //Urgent flag
    tcp->ack = 0; //Acknownledge
    tcp->psh = 0; //Push data immediately
    tcp->rst = 0; //RST flag
    tcp->syn = 1; //SYN flag
    tcp->fin = 0; //Terminates the connection
    tcp->window = htons(155);//0xFFFF; //16 bit max number of databytes 
    tcp->check = 0; //16 bit check sum. Can't calculate at this point
    tcp->urg_ptr = 0; //16 bit indicate the urgent data. Only if URG flag is set

    //Now we can calculate the checksum for the TCP header
    pTCPPacket.srcAddr = inet_addr(spoofed_address); //32 bit format of source address
    pTCPPacket.dstAddr = inet_addr(target_address); //32 bit format of source address
    pTCPPacket.zero = 0; //8 bit always zero
    pTCPPacket.protocol = IPPROTO_TCP; //8 bit TCP protocol
    pTCPPacket.TCP_len = htons(sizeof(struct tcphdr) + strlen(data)); // 16 bit length of TCP header

    //Populate the pseudo packet
    pseudo_packet = (char *) malloc((int) (sizeof(struct pseudoTCPPacket) + sizeof(struct tcphdr) + strlen(data)));
    memset(pseudo_packet, 0, sizeof(struct pseudoTCPPacket) + sizeof(struct tcphdr) + strlen(data));

    //Copy pseudo header
    memcpy(pseudo_packet, (char *) &pTCPPacket, sizeof(struct pseudoTCPPacket));

    //Copy tcp header + data to fake TCP header for checksum
    memcpy(pseudo_packet + sizeof(struct pseudoTCPPacket), tcp, sizeof(struct tcphdr) + strlen(data));

    //Set the TCP header's check field
    tcp->check = (csum((unsigned short *) pseudo_packet, (int) (sizeof(struct pseudoTCPPacket) + 
          sizeof(struct tcphdr) +  strlen(data))));

    if (sendto(client, packet, ip->tot_len, 0, (struct sockaddr *)&din, sizeof(din)) < 0)
    {
        fprintf(stderr, "Chyba pri odesilani dat pres socket.\n");
        exit(1);
    }
}

/*********************************************************************************************
 *     
 *   sniffer co zachycuje na konkretnim rozhrani pakety jdouci na jeho konkretni rozhrani
 *
 *********************************************************************************************/
void *interface_sniffer(void *arg)
{

    struct interface_sniffer_arguments *args = (struct interface_sniffer_arguments *)arg;

    char errbuf[PCAP_ERRBUF_SIZE]; /* Error string */
    bpf_u_int32 mask;              /* Our netmask */
    bpf_u_int32 net;               /* Our IP */
    struct pcap_pkthdr header;     /* The header that pcap gives us */
    const unsigned char *packet;   /* The actual packet */

    if (pcap_lookupnet(args->ifc, &net, &mask, errbuf) == -1)
    {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", args->ifc, errbuf);
        net = 0;
        mask = 0;
    }
    pcap_t *ifc_sniff = pcap_open_live(args->ifc, BUFSIZ, 1, 1000, errbuf); // 1514, 4000
    if (ifc_sniff == NULL)
    {
        fprintf(stderr, "Couldn't open device %s: %s\n", args->ifc, errbuf);
        //free(args->end_of_evangelion);
        //free(args->local_list);
        //free(args);
        exit(1);
    }
    int retv;

    // argumenty pro interface callback

    struct interface_callback_arguments *interface_callback_arg = malloc(sizeof(struct interface_callback_arguments));
    if (interface_callback_arg == NULL)
    {
        fprintf(stderr, "Chyba alokaci pameti.\n");
        exit(1);
    }
    interface_callback_arg->end_of_evangelion = malloc(sizeof(bool *));
    if (interface_callback_arg->end_of_evangelion == NULL)
    {
        fprintf(stderr, "Chyba alokaci pameti.\n");
        exit(1);
    }
    interface_callback_arg->sniff = malloc(sizeof(pcap_t *));
    if (interface_callback_arg->sniff == NULL)
    {
        fprintf(stderr, "Chyba alokaci pameti.\n");
        exit(1);
    }
    interface_callback_arg->local_list = malloc(args->pt_arr_size * sizeof(struct port *));
    if (interface_callback_arg->local_list == NULL)
    {
        fprintf(stderr, "Chyba alokaci pameti.\n");
        exit(1);
    }
    for (int i = 0; i < args->pt_arr_size; i++)
        interface_callback_arg->local_list[i] = args->local_list[i];
    memset(interface_callback_arg->target, '\0', 16);
    strcpy(interface_callback_arg->target, args->target);
    interface_callback_arg->end_of_evangelion = args->end_of_evangelion;
    interface_callback_arg->sniff = ifc_sniff;
    interface_callback_arg->min_port = args->min_port;
    interface_callback_arg->local_address_counter = args->local_address_counter;

    for (int i = 0; i < args->local_address_counter; i++)
    {
        memset(interface_callback_arg->local_addresses[i], '\0', 16);
        strcpy(interface_callback_arg->local_addresses[i], args->local_addresses[i]);
    }

    retv = pcap_loop(ifc_sniff, -1, (pcap_handler)interface_callback, (unsigned char *)interface_callback_arg);
    // z callbacku byl zavolan breakloop
    if (retv != -2 && retv < 0)
    {
        fprintf(stderr, "cannot get raw packet: %s\n", pcap_geterr(ifc_sniff));
        //free(args->end_of_evangelion);
        //free(args->local_list);
        //free(args);
        exit(1);
    }

    pcap_close(ifc_sniff);

    //free(args->end_of_evangelion);
    //free(args->local_list);
    //free(args);

    return NULL;
}

/*********************************************************************************************
 *     
 *   callback interface snifferu
 *
 *********************************************************************************************/
void interface_callback(struct interface_callback_arguments *arg, const struct pcap_pkthdr *header, const unsigned char *packet)
{

    arg = (struct interface_callback_arguments *)arg;

    // jeste neni konec
    if (!(*arg->end_of_evangelion))
    {

        struct ether_header* eth;
        struct iphdr* ip;
        struct tcphdr* tcp;

	    packet += sizeof(struct ether_header);
        ip = (struct iphdr*)packet;

        char srcname[16];
        inet_ntop(AF_INET, &ip->saddr, srcname, INET_ADDRSTRLEN);

        if (!strcmp(srcname, arg->target))
        {

            char dstname[16];
            inet_ntop(AF_INET, &ip->daddr, dstname, INET_ADDRSTRLEN);

            for (int i = 0; i < arg->local_address_counter; i++)
            {
                if (!strcmp(dstname, arg->local_addresses[i]))
                { // jestli je cilova adresa v poli lokalnich adres

                    printf("--PAKET--\n");

                    // start analyzy obsahu paketu
                    if (ip->protocol == 6)
                    { // je to tcp, takze RST/SYN/SYNACK

                        tcp = (struct tcphdr*)(packet+ ip->ihl * 4);

                        if (tcp->th_flags & TH_SYN)
                        { // SYN i ACK SYN
                            printf("nalezen paket s syn/ack syn\n");
                            unsigned short srcport = ntohs(tcp->th_sport);
                            printf("port: %i\n",srcport);
                            if (arg->local_list[srcport - arg->min_port]->port != 0) {
                                arg->local_list[srcport - arg->min_port]->passed = true;
                                printf("v local seznamu neni na pozici 0, paket s portem na passed.\n");
                            }
                            else {
                                printf("v seznamu byla 0.\n");
                            }
                        }
                        else if (tcp->th_flags & TH_RST)
                        {
                            printf("nalezen paket s RST.\n");
                            unsigned short srcport = ntohs(tcp->th_sport);
                            (arg->local_list[srcport - arg->min_port]->rst)++;
                        }
                    }
                }
            }
        }
    }
    else
        pcap_breakloop(arg->sniff);

    //free(arg->sniff);
    //free(arg->local_list);
    //free(arg->end_of_evangelion);
    //free(arg);
}

/*********************************************************************************************
 *     
 *   ziskej vsechna rozhrani
 *   http://man7.org/linux/man-pages/man3/getifaddrs.3.html pro pokrocile moznosti a ipv6
 *
 *********************************************************************************************/
struct single_interface *getInterface(int *interfaces_count)
{

    // vytvor argumenty co pujdou do *interfaces
    struct single_interface *interfaces = malloc(10 * sizeof(struct single_interface)); // pole max. deseti interfaces
    if (interfaces == NULL)
    {
        fprintf(stderr, "Chyba alokace pameti.\n");
        exit(1);
    }
    struct ifaddrs *ifaddr, *ifa;
    int family, s, n, m;
    char host[16];
    char mask[16];

    if (getifaddrs(&ifaddr) == -1)
    {
        fprintf(stderr, "Chyba pri getifaddress.\n");
        exit(1);
    }

    for (ifa = ifaddr, n = 0; ifa != NULL; ifa = ifa->ifa_next, n++)
    {

        if (ifa->ifa_addr == NULL)
            continue;

        family = ifa->ifa_addr->sa_family;

        if (family == AF_INET)
        {

            s = getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in), host, 16, NULL, 0, NI_NUMERICHOST);
            m = getnameinfo(ifa->ifa_netmask, sizeof(struct sockaddr_in), mask, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
            if (s != 0)
            {
                fprintf(stderr, "Getnameinfo() failed: %s.s\n", gai_strerror(s));
                exit(1);
            }

            if (!strcmp(host, "127.0.0.1"))
            { // localhosst skip. BUG: dalsi adresy
                continue;
            }

            // napln konkretni rozhrani
            memset(interfaces[*interfaces_count].mask, '\0', 16);
            memset(interfaces[*interfaces_count].name, '\0', 20);
            memset(interfaces[*interfaces_count].ip, '\0', 16);
            strcpy(interfaces[*interfaces_count].mask, mask);
            strcpy(interfaces[*interfaces_count].ip, host);
            strcpy(interfaces[*interfaces_count].name, ifa->ifa_name);
            interfaces[*interfaces_count].usable = false;

            (*interfaces_count)++;
        }
    }

    freeifaddrs(ifaddr);
    return interfaces;
}

/*********************************************************************************************
 *     
 * vygeneruj decoy pro jedno konkretni rozhrani
 * pocet dalsich pripadnych pouzitych rozhrani osetri post. nahrazovanim v **addresses z funkce main()
 *
 *********************************************************************************************/
void generate_decoy_ips(struct single_interface interface, int *passed_interfaces, struct single_address *addresses, int *decoy_count, int client, char *target, struct sockaddr_in *target_struct)
{ // https://stackoverflow.com/questions/44295654/print-all-ips-based-on-ip-and-mask-c

    struct in_addr ipaddress, subnetmask;

    inet_pton(AF_INET, interface.ip, &ipaddress);
    inet_pton(AF_INET, interface.mask, &subnetmask);

    unsigned long interface_ip = ntohl(ipaddress.s_addr);
    unsigned long first_ip = ntohl(ipaddress.s_addr & subnetmask.s_addr);
    unsigned long last_ip = ntohl(ipaddress.s_addr | ~(subnetmask.s_addr));

    char decoy[16];    // decoy adresa
    int add_decoy = 0; // lokalni iterator poctu pridavanych decoys z jednoho rozhrani

    // pro kazdou subadresu v siti spust decoy ping test
    for (unsigned long ip = first_ip; ip <= last_ip; ++ip)
    {

        unsigned long theip = htonl(ip);

        if (add_decoy == (DECOYS / *passed_interfaces)) // uz dosahl plneho pole pro tuto n-tou iteraci
            break;

        if (ip == first_ip || ip == last_ip || ip == interface_ip) // sit ani broadcast nechces
            continue;

        inet_ntop(AF_INET, &theip, decoy, INET_ADDRSTRLEN);
        decoy_ping_succ = false; // pokud je adresa pouzivana, vrati true

        // argumenty pro decoy ping
        struct ping_arguments *ping_arg = malloc(sizeof(struct ping_arguments));
        ping_arg->target_struct = malloc(sizeof(struct sockaddr_in *));
        if (ping_arg == NULL)
        {
            fprintf(stderr, "Chyba pri alokaci pameti.");
            exit(1);
        }
        ping_arg->ok = malloc(sizeof(bool *));
        if (ping_arg->ok == NULL)
        {
            fprintf(stderr, "Chyba pri alokaci pameti.");
            exit(1);
        }
        if (ping_arg->target_struct == NULL)
        {
            fprintf(stderr, "Chyba pri alokaci pameti.");
            exit(1);
        }
        memset(ping_arg->target, '\0', 16);
        memset(ping_arg->ifc, '\0', 20);
        memset(ping_arg->ip, '\0', 16);
        strcpy(ping_arg->target, decoy);
        strcpy(ping_arg->ip, interface.ip);
        strcpy(ping_arg->ifc, interface.name);
        ping_arg->client = client;
        ping_arg->ok = &decoy_ping_succ;

        // decoy target override
        struct hostent *hname;
        struct sockaddr_in decoy_target;
        hname = gethostbyname(decoy);
        memset(&decoy_target, '\0', sizeof(decoy_target));
        decoy_target.sin_family = hname->h_addrtype;
        decoy_target.sin_port = 0;
        decoy_target.sin_addr.s_addr = *(long *)hname->h_addr_list[0];
        ping_arg->target_struct = &decoy_target;

        ping(ping_arg);

        if (decoy_ping_succ) { // pingovana adresa je pouzivana, pokracuj
            decoy_ping_succ = false;
        }
        else
        { 
            // pridej adresu do pole addresses a dokud jich neni %DECOYS, pokracuj
            if (add_decoy < (DECOYS / *passed_interfaces))
            {
                memset(addresses[add_decoy].ip, '\0', 16); // mel by tu s vyssim poctem rozh by add_decoy
                strcpy(addresses[add_decoy].ip, decoy);
                addresses[add_decoy].cidr = cidr(interface.mask);
                memset(addresses[add_decoy].ifc, '\0', 20);
                strcpy(addresses[add_decoy].ifc, interface.name);

                add_decoy++; // lokalni iterator
                (*decoy_count)++; // globalni iterator decoy adres
            }
        }
    }
}

/*********************************************************************************************
 *     
 * prevod masky site na cidr
 * https://stackoverflow.com/questions/6657475/netmask-conversion-to-cidr-format-in-c
 * 
 *********************************************************************************************/
static unsigned short cidr(char* ipAddress)
  {
      unsigned short netmask_cidr;
      int ipbytes[4];

      netmask_cidr=0;
      sscanf(ipAddress, "%d.%d.%d.%d", &ipbytes[0], &ipbytes[1], &ipbytes[2], &ipbytes[3]);

      for (int i=0; i<4; i++)
      {
          switch(ipbytes[i])
          {
              case 0x80:
                  netmask_cidr+=1;
                  break;

              case 0xC0:
                  netmask_cidr+=2;
                  break;

              case 0xE0:
                  netmask_cidr+=3;
                  break;

              case 0xF0:
                  netmask_cidr+=4;
                  break;

              case 0xF8:
                  netmask_cidr+=5;
                  break;

              case 0xFC:
                  netmask_cidr+=6;
                  break;

              case 0xFE:
                  netmask_cidr+=7;
                  break;

              case 0xFF:
                  netmask_cidr+=8;
                  break;

              default:
                  return netmask_cidr;
                  break;
          }
      }

      return netmask_cidr;
  }

/*********************************************************************************************
 *     
 * vyber random port
 *
 *********************************************************************************************/
int rndm(int lower, int upper)
{
    return (rand() % (upper - lower + 1)) + lower;
}

/*********************************************************************************************
 *     
 * vyber cekaci cas v microsec
 *
 *********************************************************************************************/
unsigned long rndmsleep(unsigned long lower, unsigned long upper)
{
    return (rand() % (upper - lower + 1)) + lower;
}

/*********************************************************************************************
 *     
 * vyber nahodnou delku retezce
 *
 *********************************************************************************************/
unsigned short rndmstr(unsigned short lower, unsigned short upper)
{
    return (rand() % (upper - lower + 1)) + lower;
}

/*********************************************************************************************
 *     
 * rizeni celeho jednoho interface
 *
 *********************************************************************************************/
void *interface_looper(void *arg)
{

    pthread_t ifc_sniff;
    pthread_t ifc_handler;
    struct interface_arguments *args = (struct interface_arguments *)arg;

    // vytvor tabulku s lokalnimi ip adresami tohoto rozhrani + jeji counter
    local_address local_addresses[DECOYS + 1];
    int local_address_counter = 0;
    for (int i = 0; i < DECOYS; i++) // pridej + 1 pokud je tu rozhrani taky
    {
        if (!strcmp(args->addresses[i].ifc, args->ifc))
        {
            memset(local_addresses[local_address_counter], '\0', 16);
            strcpy(local_addresses[local_address_counter], args->addresses[i].ip);
            local_address_counter++;
        }
    }

    /*printf("--LOCAL ADDRESSES IFC--\n");
    printf("adres count: %i\n",local_address_counter);
    for(int i = 0; i < local_address_counter; i++)
        printf("%s\n",local_addresses[i]);*/

    // lokalni seznam portu ke zpracovani na tomhle interface
    struct port *local_list = malloc(sizeof(struct port) * args->pt_arr_size);
    if (local_list == NULL)
    {
        fprintf(stderr, "Chyba pri alokaci pameti.\n");
        exit(1);
    }
    for (int i = 0; i < args->pt_arr_size; i++)
    {
        local_list[i].port = 0;
        local_list[i].passed = false;
        local_list[i].count = 0;
        local_list[i].rst = 0;
    }

    /*printf("--INITIAL LOCAL LIST IFC--\n");
    for(int i = 0; i < args->pt_arr_size; i++)
        printf("%i\n",local_list[i].port);*/

    int local_list_counter = 0; // pocet polozek v lokalnim listu
    // zda je lokalni list prazdny - zapne to handler, zacne konec interface
    bool interface_killer = false;
    // zapne to interface, zacne konec snifferu
    bool komm_susser_todd = false;

    // vytvor argumenty interface snifferu
    struct interface_sniffer_arguments *interface_sniff_arg = malloc(sizeof(struct interface_sniffer_arguments));
    if (interface_sniff_arg == NULL)
    {
        fprintf(stderr, "Chyba pri alokaci pameti.\n");
        exit(1);
    }
    interface_sniff_arg->end_of_evangelion = malloc(sizeof(bool *));
    if (interface_sniff_arg->end_of_evangelion == NULL)
    {
        fprintf(stderr, "Chyba pri alokaci pameti.\n");
        exit(1);
    }
    interface_sniff_arg->local_list = malloc(args->pt_arr_size * sizeof(struct port *));
    if (interface_sniff_arg->local_list == NULL)
    {
        fprintf(stderr, "Chyba pri alokaci pameti.\n");
        exit(1);
    }
    for (int i = 0; i < args->pt_arr_size; i++)
    {
        interface_sniff_arg->local_list[i] = &local_list[i];
    }
    memset(interface_sniff_arg->ifc, '\0', 20);
    strcpy(interface_sniff_arg->ifc, args->ifc);
    memset(interface_sniff_arg->target, '\0', 16);
    strcpy(interface_sniff_arg->target, args->target_address);
    interface_sniff_arg->end_of_evangelion = &komm_susser_todd;
    for (int i = 0; i < local_address_counter; i++)
    {
        memset(interface_sniff_arg->local_addresses[i], '\0', 16);
        strcpy(interface_sniff_arg->local_addresses[i], local_addresses[i]);
    }
    interface_sniff_arg->local_address_counter = local_address_counter;
    interface_sniff_arg->pt_arr_size = args->pt_arr_size;
    interface_sniff_arg->min_port = args->min_port;

    // vytvor argumenty interface handleru
    struct interface_handler_arguments *interface_handler_arg = malloc(sizeof(struct interface_handler_arguments));
    if (interface_handler_arg == NULL)
    {
        fprintf(stderr, "Chyba pri alokaci pameti.\n");
        exit(1);
    }
    interface_handler_arg->interface_killer = malloc(sizeof(bool *));
    if (interface_handler_arg->interface_killer == NULL)
    {
        fprintf(stderr, "Chyba pri alokaci pameti.\n");
        exit(1);
    }
    interface_handler_arg->local_list = malloc(args->pt_arr_size * sizeof(struct port *));
    if (interface_handler_arg->local_list == NULL)
    {
        fprintf(stderr, "Chyba pri alokaci pameti.\n");
        exit(1);
    }
    interface_handler_arg->local_list_counter = malloc(sizeof(int *));
    if (interface_handler_arg->local_list_counter == NULL)
    {
        fprintf(stderr, "Chyba pri alokaci pameti.\n");
        exit(1);
    }
    interface_handler_arg->interface_killer = &interface_killer;
    interface_handler_arg->local_list_counter = &local_list_counter;
    interface_handler_arg->pt_arr_size = args->pt_arr_size;
    for (int i = 0; i < args->pt_arr_size; i++)
    {
        interface_handler_arg->local_list[i] = &local_list[i];
    }

    // vytvor port sniffer a nahraj do nej argumenty
    if (pthread_create(&ifc_sniff, NULL, interface_sniffer, (void *)interface_sniff_arg))
    {
        fprintf(stderr, "Chyba pri vytvareni vlakna.\n");
        //free(args->addresses);
        //free(args);
        exit(1);
    }

    // vytvor port handler a nahraj do nej argumenty
    if (pthread_create(&ifc_handler, NULL, interface_handler, (void *)interface_handler_arg))
    {
        fprintf(stderr, "Chyba pri vytvareni vlakna.\n");
        //free(args->addresses);
        //free(args);
        exit(1);
    }

    // spocitej kolik domen je v tomto interface
    int domain_counter = 0;
    for (int i = 0; i < args->decoy_count; i++)
    {
        if (!strcmp(args->addresses[i].ifc, args->ifc))
        {
            domain_counter++;
        }
    }
    // vytvor vlakna z decoy domen, pocet domen v interface
    pthread_t domain[domain_counter];
    void *retval[domain_counter];
    int c = 0; // vnitrni pocitadlo generatoru vlaken

    for (int i = 0; i < domain_counter; i++)
    {
        if (!strcmp(args->addresses[i].ifc, args->ifc))
        {
            struct domain_arguments *domain_arg = malloc(sizeof(struct domain_arguments));
            domain_arg->local_list = malloc(args->pt_arr_size * sizeof(struct port *));
            if (domain_arg->local_list == NULL)
            {
                fprintf(stderr, "Chyba pri alokaci pameti.\n");
                exit(1);
            }
            domain_arg->end_of_evangelion = malloc(sizeof(bool *));
            if (domain_arg->end_of_evangelion == NULL)
            {
                fprintf(stderr, "Chyba pri alokaci pameti.\n");
                exit(1);
            }
            domain_arg->local_list_counter = malloc(sizeof(int *));
            if (domain_arg == NULL)
            {
                fprintf(stderr, "Chyba pri alokaci pameti.\n");
                exit(1);
            }
            if (domain_arg->local_list_counter == NULL)
            {
                fprintf(stderr, "Chyba pri alokaci pameti.\n");
                exit(1);
            }
            domain_arg->local_list_counter = &local_list_counter;
            domain_arg->min_port = args->min_port;
            for (int i = 0; i < args->pt_arr_size; i++)
            {
                domain_arg->local_list[i] = &local_list[i];
            }
            domain_arg->client = args->client;
            memset(domain_arg->target_address, '\0', 16);
            strcpy(domain_arg->target_address, args->target_address);
            domain_arg->pt_arr_size = args->pt_arr_size;
            memset(domain_arg->ip, '\0', 16);
            strcpy(domain_arg->ip, args->addresses[i].ip);
            domain_arg->end_of_evangelion = &komm_susser_todd;

            pthread_create(&domain[c++], NULL, domain_loop, (void *)domain_arg);
        }
    }

    // smycka rozhrani ceka na local_list_empty of handleru
    // ifc se vypne kdyz je lokalni seznam i globalni seznam prazdny
    // muzeme jen doufat ze se nevypnou uplne vsechny zaraz i kdyz nekde neco bude
    while (true)
    {
        sleep(5);
        if (interface_killer && queue_isEmpty(global_queue->count))
        {
            break;
        }
    }
    komm_susser_todd = true; // ukonci sniffer

    // pockej na zbytek deti
    for (int i = 0; i < domain_counter; i++)
        pthread_join(domain[i], &retval[i]);

    // pockej na port sniffer
    pthread_join(ifc_sniff, NULL);

    //free(args->addresses);
    //free(args);

    return NULL;
}

/*********************************************************************************************
 *     
 * interface handler
 *
 *********************************************************************************************/
void *interface_handler(void *arg)
{

    // rozbal argumenty
    struct interface_handler_arguments *args = (struct interface_handler_arguments *)arg;

    // 1. varovani, pockej dalsich pet sekund..
    bool semi_empty = false;
    // casova znamka jednoho prubehu handleru
    struct timeval timestamp;

    // dokud v lokalnim listu neco je
    while (true)
    {
        sleep(SLEEP_TIME);
        if (semi_empty)
        {
            if (*args->local_list_counter == 0)
                break;
            else
                semi_empty = false;
        }
        if (*args->local_list_counter == 0)
        {
            semi_empty = true;
            continue;
        }
        // tady zacina standartni prochazeni seznamu
        gettimeofday(&timestamp, NULL);
        for (int i = 0; i < args->pt_arr_size; i++)
        {
            if (args->local_list[i]->port != 0 && ((timestamp.tv_sec - args->local_list[i]->time.tv_sec) >= SLEEP_TIME))
            {
                if (args->local_list[i]->passed)
                { // aktivni port
                    printf("TCP PORT %i OPEN\n", args->local_list[i]->port);
                    args->local_list[i]->port = 0;
                    (*args->local_list_counter)--;
                }
                else
                { // neaktivni port
                    if (args->local_list[i]->count < 2)
                    { // posli ho zpet do fronty
                        (args->local_list[i]->count)++;
                        queue_insert(*args->local_list[i], &(global_queue->rear), args->pt_arr_size, global_queue->q, &(global_queue->count));
                        args->local_list[i]->port = 0;
                        (*args->local_list_counter)--;
                    }
                    else
                    {
                        if ((*args->local_list[i]).rst == 2)
                        { // pokazde se vratil RST, opravdu zavreny
                            printf("TCP PORT %i CLOSED\n", (*args->local_list[i]).port);
                            args->local_list[i]->port = 0;
                            (*args->local_list_counter)--;
                        }
                        else
                        { // pri nejakem pokusu napriklad nevratil nic
                            printf("TCP PORT %i FILTERED\n", (*args->local_list[i]).port);
                            args->local_list[i]->port = 0;
                            (*args->local_list_counter)--;
                        }
                    }
                }
            }
        }
    }
    (*args->interface_killer) = true; // timhle rikas interface aby vypnulo sniffer

    return NULL;
}

/*********************************************************************************************
 *     
 * konkretni domena na rozhrani
 *
 *********************************************************************************************/
void *domain_loop(void *arg)
{

    struct timeval timestamp;
    int spoofed_port;

    // rozbal argumenty
    struct domain_arguments *args = (struct domain_arguments *)arg;

    // mel by to vypnout handler
    while (!(*args->end_of_evangelion))
    {

        // spoofed port ze kteryho odesles SYN
        spoofed_port = rndm(PORT_RANGE_START, PORT_RANGE_END);

        // z fronty vezmi port
        if (!queue_isEmpty(global_queue->count))
        {
            struct port worked_port = queue_removeData(global_queue->q, &(global_queue->front), args->pt_arr_size, &(global_queue->count));

            // zpracovany port dej do local listu
            (*args->local_list[worked_port.port - args->min_port]).count = worked_port.count;
            (*args->local_list[worked_port.port - args->min_port]).port = worked_port.port;
            (*args->local_list[worked_port.port - args->min_port]).passed = worked_port.passed;
            gettimeofday(&timestamp, NULL);
            (*args->local_list[worked_port.port - args->min_port]).time.tv_sec = timestamp.tv_sec;
            // zvys citatc lokalniho seznamu
            (*args->local_list_counter)++;
            // odesli na port
            send_syn(spoofed_port, worked_port.port, args->ip, args->target_address, args->client);

            /*printf("--LOCAL LIST STATUS--\n");
            for(int i = 0; i < args->pt_arr_size; i++)
                printf("%i\n",args->local_list[i]->port);*/
        }

        // cekej mezi 0.5-1 s
        usleep(rndmsleep(500000, 1000000));
    }

    return NULL;
}

/*********************************************************************************************
 *     
 * randomizuj pole portu
 *
 *********************************************************************************************/
void randomize(struct port *array, int n)
{
    if (n > 1)
    {
        size_t i;
        for (i = 0; i < n - 1; i++)
        {
            size_t j = i + rand() / (RAND_MAX / (n - i) + 1);
            struct port t = array[j];
            array[j] = array[i];
            array[i] = t;
        }
    }
}

/*********************************************************************************************
 *     
 * zkontroluj argumenty programu
 *
 *********************************************************************************************/
int checkArg(char *argument)
{

    int range = 0; // -
    int col = 0;   // ,
    for (int i = 0; i < strlen(argument); i++)
    {
        if (isdigit(argument[i]))
        {
            continue;
        }
        else if (argument[i] == '-')
        {
            range++;
        }
        else if (argument[i] == ',')
            col++;
        else
            return 0;
    }
    if (range > 1 || !isdigit(argument[strlen(argument) - 1]) || (range > 0 && col > 0))
    {
        return 0;
    }

    if (range == 1)
    {
        return 1; // je tam jedna pomlcka
    }
    else if (col > 1)
        return 2; // jsou tam carky
    else
        return 3; // jsou tam jen cisla
}

/*********************************************************************************************
 *     
 * parsovani argumentu programu
 *
 *********************************************************************************************/
int getCharCount(char *str, char z)
{
    int c = 0;
    for (int i = 0; i < strlen(str); i++)
    {
        if (str[i] == z)
            c++;
    }
    return c;
}

/*********************************************************************************************
 *     
 * funkce ke globalni fronte portu
 *
 *********************************************************************************************/

bool queue_isEmpty(int count)
{
    return count == 0;
}
bool queue_isFull(int count, int max)
{ // prebytecne, k preplneni nedojde
    return count == max;
}
int queue_size(int count)
{ // dat mutex
    pthread_mutex_lock(&mutex_queue_size);
    return count;
    pthread_mutex_unlock(&mutex_queue_size);
}
void queue_insert(struct port data, int *rear, int max, struct port *q, int *count)
{
    pthread_mutex_lock(&mutex_queue_insert);
    if (!queue_isFull(*count, max))
    {
        if (*rear == max - 1)
        {
            *rear = -1;
        }
        q[++(*rear)] = data;
        (*count)++;
    }
    pthread_mutex_unlock(&mutex_queue_insert);
}
struct port queue_removeData(struct port *q, int *front, int max, int *count)
{ // dat mutex
    pthread_mutex_lock(&mutex_queue_remove);

    struct port data = q[(*front)++];
    if (*front == max)
    {
        *front = 0;
    }
    (*count)--;
    pthread_mutex_unlock(&mutex_queue_remove);
    return data;
}

/*********************************************************************************************
 *     
 * funkce ke zprocesovani argumentu pt a pu
 *
 *********************************************************************************************/

void processArgument(int ret_px, struct port **px_arr, int *px_arr_size, char *px)
{

    // pocet clenu portu
    int size = 0;

    if (ret_px == 1)
    { // hledas -
        struct port *px_arr_subst = malloc(sizeof(struct port) * 2);
        if (px_arr_subst == NULL)
        {
            fprintf(stderr, "Chyba pri alokaci.\n");
            exit(1);
        }
        int i = 0;
        char *end;
        char *p = strtok(px, "-");
        while (p)
        {
            px_arr_subst[i].port = (int)strtol(p, &end, 10);
            p = strtok(NULL, "-");
            i++;
        }
        size = px_arr_subst[1].port - px_arr_subst[0].port + 1;
        *px_arr_size = size;
        *px_arr = malloc(sizeof(struct port) * size);
        if (*px_arr == NULL)
        {
            fprintf(stderr, "Chyba pri alokaci.\n");
            exit(1);
        }

        for (int j = 0; j < *px_arr_size; j++)
        {
            px_arr[j]->port = px_arr_subst[0].port + j;
            px_arr[j]->count = 0;
            px_arr[j]->passed = false;
        }
        //free(px_arr_subst);
    }
    else if (ret_px == 2)
    { // hledas ,
        int l = getCharCount(px, ',');
        *px_arr = malloc(sizeof(struct port) * (l + 1));
        size = l + 1;
        if (px_arr == NULL)
        {
            fprintf(stderr, "Chyba pri alokaci.\n");
            exit(1);
        }
        int i = 0;
        char *end;
        char *p = strtok(px, ",");
        while (p)
        {
            px_arr[i]->port = (int)strtol(p, &end, 10);
            px_arr[i]->count = 0;
            px_arr[i]->passed = false;
            px_arr[i]->rst = 0;
            p = strtok(NULL, ",");
            i++;
        }
        *px_arr_size = size;
    }
    else
    { // vkladas cely cislo do pole
        *px_arr = malloc(sizeof(struct port));
        char *end;
        if (px_arr == NULL)
        {
            fprintf(stderr, "Chyba pri alokaci.\n");
            exit(1);
        }
        px_arr[0]->port = (int)strtol(px, &end, 10);
        px_arr[0]->count = 0;
        px_arr[0]->passed = false;
        size = 1;
        *px_arr_size = 1;
    }

    for (int i = 0; i < size; i++)
    {
        if (px_arr[i]->port > 65535 || px_arr[i]->port < 0)
        {
            fprintf(stderr, "Spatny rozsah cisla portu (0 - 65535).\n");
            exit(1);
        }
    }
}