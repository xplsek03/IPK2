#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>
#include <pthread.h>
#include <getopt.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <stdbool.h>
#include <ctype.h>
#include <netdb.h>
#include <pcap.h>
#define RAND_MAX 2147483647
#ifndef FUNCTIONS_H
#include "functions.h"
#endif
#ifndef PING_H
#include "ping.h"
#endif
pthread_mutex_t mutex_queue_remove = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t mutex_queue_size = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t mutex_queue_insert = PTHREAD_MUTEX_INITIALIZER;
bool decoy_ping_succ; // urceni zda ping cileny na decoy domenu prosel

struct single_address *addresses; // globalni seznam adres
struct port *global_list_tcp; // globalni seznam prave zpracovavanych portu
struct port *global_list_udp; // globalni seznam udp portu
struct queue *global_queue_tcp; // globalni fronta portu ke zpracovani
struct queue *global_queue_udp; // globalni fronta portu ke zpracovani
pcap_t *sniff; // globalni sniffer na ping
bool alarm_signal; // globalni alarm co signalizuje, jestli se vypnul pomoci casu

int main(int argc, char **argv) {
    srand(time(0)); // zamichej cislama

    ///////////////////////////////////////////////////////////
    // OBECNE ZPRACOVANI ARGUMENTU
    ///////////////////////////////////////////////////////////

	// promenne pro validaci argumentu
    char *pu;
    char *pt;
    char *host;
    char *intfc;
    int puc = 0;
    int ptc = 0;
    int hc = 0;
    int ic = 0;
    
    // pole pro seznam 
    struct port *pu_arr;
    struct port *pt_arr;
    
    // kontrola poctu argumentu
    if(argc != 6 && argc != 4 && argc != 8) {
        fprintf(stderr,"Spatne zadane argumenty programu.\n");
        return 1;
    }

    // nalezeni argumentu
    for(int i = 1; i < argc; i++) {
        if(!strcmp(argv[i],"-pu")) {
            if(i == argc-1) {
                fprintf(stderr,"Spatne zadane argumenty programu.\n");
                return 1;
            }
            else {
                pu = argv[i+1];
                i++;
                puc++;
            }
        }
        else if(!strcmp(argv[i],"-pt")) {
            if(i == argc-1) {
                fprintf(stderr,"Spatne zadane argumenty programu.\n");
                return 1;
            }
            else {
                pt = argv[i+1];
                i++;
                ptc++;
            }
        }
        else if(!strcmp(argv[i],"-i")) {
            if(i == argc-1) {
                fprintf(stderr,"Spatne zadane argumenty programu.\n");
                return 1;
            }
            else {
                intfc = argv[i+1];
                i++;
                ic++;
            }
        }
        else {
            host = argv[i];
            hc++;
        }
    }

    // validace nalezenych argumentu
    if(puc > 1 || ptc > 1 || hc != 1 || ic > 1) {
        fprintf(stderr,"Spatne zadane argumenty programu.\n");
        return 1;
    }

    // alespon jeden z argumentu
    if(!puc && !ptc) {
        fprintf(stderr,"Spatne zadane argumenty programu.\n");
        return 1;       
    }

    int ret_pt;
    int ret_pu;
    // co jsou oba argumenty zac, jestli range, vycet..
    if(puc) {
        ret_pu = checkArg(pu);
        if(!ret_pu) {
            fprintf(stderr,"Spatne zadane argumenty programu.\n");
            return 1;
        }
    }
    if(ptc) {
        ret_pt = checkArg(pt);
        if(!ret_pt) {
            fprintf(stderr,"Spatne zadane argumenty programu.\n");
            return 1;
        }
    }


    // celkovy pocet portu
    int pu_arr_size = 0;
    int pt_arr_size = 0;
    // minimalni porty kvuli prevedeni na pole
    int min_port_pt;
    int min_port_pu;
    // velikost pole naparsovanych portu
    int size = 0;

    // sockety
    int client_tcp;
    int client_udp;

    ///////////////////////////////////////////////////////////
    // ZPRACOVANI ARGUMENTU TCP
    ///////////////////////////////////////////////////////////

    if(ptc) {
        if(ret_pt == 1) { // hledas -
            struct port *pt_arr_subst = malloc(sizeof(struct port)*2);
            if(pt_arr_subst == NULL) {
                fprintf(stderr,"Chyba pri alokaci.\n");
                exit(1);
            }
            int i = 0;
            char *end;
            char *p = strtok(pt, "-");
            while(p) {
                pt_arr_subst[i].port = (int)strtol(p, &end, 10);
                p = strtok(NULL, "-");
                i++;
            }
            size = pt_arr_subst[1].port - pt_arr_subst[0].port +1;
            pt_arr_size = size;
            min_port_pt = pt_arr_subst[0].port;
            pt_arr = malloc(sizeof(struct port)*size);
            if(pt_arr == NULL) {
                fprintf(stderr,"Chyba pri alokaci.\n");
                exit(1);            
            }

            for(int j = 0; j < pt_arr_size; j++) {
                pt_arr[j].port = pt_arr_subst[0].port + j;
                pt_arr[j].count = 0;
                pt_arr[j].passed = false;
            }
            free(pt_arr_subst);
        }
        else if(ret_pt == 2) { // hledas ,
            int l = getCharCount(pt,',');
            pt_arr = malloc(sizeof(struct port) * (l+1));
            size = l+1;
            if(pt_arr == NULL) {
                fprintf(stderr,"Chyba pri alokaci.\n");
                exit(1);
            }
            int i = 0;
            char *end;
            char *p = strtok(pt, ",");
            while (p) {
                pt_arr[i].port = (int)strtol(p, &end, 10);
                pt_arr[i].count = 0;
                pt_arr[i].passed = false;
                pt_arr[i].rst = 0;
                p = strtok(NULL, ",");
                i++;
            }
            pt_arr_size = size;
        }
        else { // vkladas cely cislo do pole
            pt_arr = malloc(sizeof(struct port));
            char *end;
            if(pt_arr == NULL) {
                fprintf(stderr,"Chyba pri alokaci.\n");
                exit(1);
            }
            pt_arr[0].port = (int)strtol(pt, &end, 10);
            pt_arr[0].count = 0;
            pt_arr[0].passed = false;
            size = 1;
            pt_arr_size = 1;
            min_port_pt = pt_arr[0].port;
        }
        for(int i = 0; i < size; i++) {
            if(pt_arr[i].port > 65535 || pt_arr[i].port < 0) {
                fprintf(stderr,"Spatny rozsah cisla portu (0 - 65535).\n");
                exit(1);
            }
        }

        client_tcp = socket(AF_INET, SOCK_RAW, IPPROTO_RAW); // SOCKET POUZE NA TCP
        if (client_tcp < 0)  
            fprintf(stderr,"Chyba pri vytvareni socketu.\n"); 

    }
    ///////////////////////////////////////////////////////////
    // ZPRACOVANI ARGUMENTU UDP
    ///////////////////////////////////////////////////////////
    if(puc) {
        if(ret_pu == 1) { // hledas -
            struct port *pu_arr_subst = malloc(sizeof(struct port)*2);
            if(pu_arr_subst == NULL) {
                fprintf(stderr,"Chyba pri alokaci.\n");
                exit(1);
            }
            int i = 0;
            char *end;
            char *p = strtok(pt, "-");
            while(p) {
                pu_arr_subst[i].port = (int)strtol(p, &end, 10);
                p = strtok(NULL, "-");
                i++;
            }
            size = pu_arr_subst[1].port - pu_arr_subst[0].port +1;
            pu_arr_size = size;
            min_port_pu = pu_arr_subst[0].port;
            pu_arr = malloc(sizeof(struct port)*size);
            if(pu_arr == NULL) {
                fprintf(stderr,"Chyba pri alokaci.\n");
                exit(1);            
            }

            for(int j = 0; j < pu_arr_size; j++) {
                pu_arr[j].port = pu_arr_subst[0].port + j;
                pu_arr[j].count = 0;
                pu_arr[j].passed = false;
            }
            free(pu_arr_subst);
        }
        else if(ret_pu == 2) { // hledas ,
            int l = getCharCount(pu,',');
            pu_arr = malloc(sizeof(struct port) * (l+1));
            size = l+1;
            if(pu_arr == NULL) {
                fprintf(stderr,"Chyba pri alokaci.\n");
                exit(1);
            }
            int i = 0;
            char *end;
            char *p = strtok(pu, ",");
            while (p) {
                pu_arr[i].port = (int)strtol(p, &end, 10);
                pu_arr[i].count = 0;
                pu_arr[i].passed = false;
                pu_arr[i].rst = 0;
                p = strtok(NULL, ",");
                i++;
            }
            pu_arr_size = size;
        }
        else { // vkladas cely cislo do pole
            pu_arr = malloc(sizeof(struct port));
            char *end;
            if(pu_arr == NULL) {
                fprintf(stderr,"Chyba pri alokaci.\n");
                exit(1);
            }
            pu_arr[0].port = (int)strtol(pu, &end, 10);
            pu_arr[0].count = 0;
            pu_arr[0].passed = false;
            size = 1;
            pu_arr_size = 1;
            min_port_pu = pu_arr[0].port;
        }
        for(int i = 0; i < size; i++) {
            if(pu_arr[i].port > 65535 || pu_arr[i].port < 0) {
                fprintf(stderr,"Spatny rozsah cisla portu (0 - 65535).\n");
                exit(1);
            }
        }

        client_udp = socket(AF_INET, SOCK_RAW, IPPROTO_RAW); // SOCKET POUZE NA TCP
        if (client_udp < 0)  
            fprintf(stderr,"Chyba pri vytvareni socketu.\n"); 

    }

    ///////////////////////////////////////////////////////////
    // ZPRACUJ TARGET
    ///////////////////////////////////////////////////////////    
    struct hostent *hname;
	struct sockaddr_in target;
    if ((hname = gethostbyname(host)) == NULL) {
        fprintf(stderr,"Nelze prevest host na ip.\n");
        exit(1);
    }
    memcpy(&target.sin_addr, hname->h_addr_list[0], hname->h_length);
    target.sin_family = AF_INET;
    target.sin_port = htons(1337);

    ///////////////////////////////////////////////////////////
    // VYTVOR SEZNAM ROZHRANI
    ///////////////////////////////////////////////////////////

    // inicializace seznamu interfaces pro ping
    int interfaces_count = 0; // kolik existuje rozhrani ( - 1)
    struct single_interface *interfaces = getInterface(&interfaces_count);

    ///////////////////////////////////////////////////////////
    // VYTVOR SEZNAM DECOYS
    ///////////////////////////////////////////////////////////

    bool ping_succ = false; // jestli byl kazdy z pingu ok. BUG asi neni potreba

    addresses = malloc(sizeof(struct single_address)*DECOYS); // pole decoy ip adres
    if(addresses == NULL) {
        fprintf(stderr,"Chyba pri alokaci.\n");
        return 1;
    }

    bool ic_first = true; // prvni pokud pri hledani zadaneho interface
    int decoy_count = 0; // pocet ip adres
    int passed_interfaces = 0; // 0..1..2: snizuje se pocet pouzitych decoy adres z kazdeho dalsiho rozhrani

    for(int i = 0; i < interfaces_count; i++) {
        ping_succ = false; // promenna jestli byl ping ok, meneno z libpcap handleru

        // hledej vyzadane rozhrani
        if(ic_first && ic) {
            for(int j = 0; j < interfaces_count; j++) {
                if(!strcmp(interfaces[j].name,intfc))
                    i = j;
            }  
        }
        else
            ic_first = false;

        // nastav argumenty na ping
        struct ping_arguments *ping_arg = malloc(sizeof(struct ping_arguments));
        ping_arg->target_struct = malloc(sizeof(struct sockaddr_in *));
        
        if(ping_arg == NULL) {
            fprintf(stderr,"Chyba pri alokaci pameti.");
            exit(1);
        }
        if(ping_arg->target_struct == NULL) {
            fprintf(stderr,"Chyba pri alokaci pameti.");
            exit(1);
        }
        ping_arg->ok = malloc(sizeof(bool*));
        memset(ping_arg->target,'\0',16);
        memset(ping_arg->ifc,'\0',20);
        memset(ping_arg->ip,'\0',16);
        strcpy(ping_arg->target,host);
        strcpy(ping_arg->ip,interfaces[i].ip);
        strcpy(ping_arg->ifc,interfaces[i].name);
        ping_arg->ok = &ping_succ;
        ping_arg->target_struct = &target;

        if(ping(ping_arg)) { // ping prosel
            passed_interfaces++; // pocet rozhrani co prosly
            interfaces[i].usable = true; // rozhrani se da dal pouzivat, protoze se z nej da dosahnout na target
            generate_decoy_ips(interfaces[i], &passed_interfaces, addresses, &decoy_count, host, &target);

            if(decoy_count < DECOYS) { // na rozhrani neni dost volnych adres ke zneuziti
                if(ic_first) // budes tam nastavovat primarni adresu sveho rozhrani
                    break;
                else { // hledej dal
                    decoy_count = 0;
                    continue;
                }
            }
            else
                break;
        }
        // pokracuj od zacatku - 0 - pokud nenalezeno
        if(ic_first) {
            i = -1;
            ic_first = false;
        }
    }
    
    if(passed_interfaces == 0)
     {
        fprintf(stderr,"Host neexistuje nebo je nedostupny..\n");
        return 1;
    }

    if(decoy_count == 0) { // nebyly zneuzity zadne nove adresy, nastav tedy adr. rozhrani
        for(int i = 0; i < interfaces_count; i++) {
            if(interfaces[i].usable) {
                decoy_count = 1;
                memset(addresses[0].ip, '\0', 16);
                strcpy(addresses[0].ip, interfaces[i].ip);
                addresses[0].cider = cidr(interfaces[i].mask);
                memset(addresses[0].ifc, '\0', 20);
                strcpy(addresses[0].ifc, interfaces[i].name); 
                break;              
            }
        }
    }

    char ip_item[150];
    char mac[18];
    for(int i = 0; i < decoy_count; i++) {
        memset(mac,'\0',18);
        memset(ip_item,'\0',150);
        get_mac(mac, addresses[i].ifc);
        snprintf(ip_item,149,"sudo ip addr add %s/%i dev %s",addresses[i].ip, addresses[i].cider, addresses[i].ifc);
        system(ip_item);
}

    ///////////////////////////////////////////////////////////
    // VYTVOR VLAKNA S UPD A TCP
    ///////////////////////////////////////////////////////////

    // https://stackoverflow.com/questions/6127503/shuffle-array-in-c
    // vytvoreni dvou oddelenych vlaken TCP a UDP. struktura: xxp_looper -> 1 sniffer + vsechny domeny

    pthread_t udp_loop;
    pthread_t tcp_loop;
    struct xxp_arguments *tcp_loop_arg;
    struct xxp_arguments *udp_loop_arg;

    if(puc) {
        randomize(pu_arr, pu_arr_size);
        global_queue_udp = malloc(sizeof(struct queue));
        global_queue_udp->q = malloc(pu_arr_size * sizeof(struct port *));
        if(global_queue_udp == NULL) {
            fprintf(stderr,"Chyba pri alokaci pameti.\n");
            exit(1);   
        }
        if(global_queue_udp->q == NULL) {
            fprintf(stderr,"Chyba pri alokaci pameti.\n");
            exit(1);   
        }
        global_queue_udp->count = pu_arr_size;
        global_queue_udp->q = pu_arr;
        global_queue_udp->front = 0;
        global_queue_udp->rear = -1;

        global_list_udp = malloc(pu_arr_size * sizeof(struct port));
        if(global_list_udp == NULL) {
            fprintf(stderr,"Chyba pri alokaci pameti.\n");
            exit(1);   
        }
        for(int i = 0; i < pu_arr_size; i++) {
            global_list_udp[i].port = 0;
            global_list_udp[i].passed = false;
            global_list_udp[i].count = 0;
            global_list_udp[i].rst = 0;
        }

        udp_loop_arg = malloc(sizeof(struct xxp_arguments));
        if(udp_loop_arg == NULL) {
            fprintf(stderr,"Chyba pri alokaci pameti.\n");
            exit(1);        
        }
        memset(udp_loop_arg->ifc,'\0',20);
        strcpy(udp_loop_arg->ifc,addresses[0].ifc);
        memset(udp_loop_arg->target_address,'\0',16);
        strcpy(udp_loop_arg->target_address,host);
        udp_loop_arg->port_count = pu_arr_size;
        udp_loop_arg->decoy_count = decoy_count;
        udp_loop_arg->client = client_udp;
        udp_loop_arg->min_port = min_port_pu;
        udp_loop_arg->xxp = false; // true = tcp, false = udp

        if (pthread_create(&udp_loop, NULL, xxp_looper, (void *)udp_loop_arg)) {
            fprintf(stderr, "Chyba pri vytvareni vlakna.\n");
            exit(1);
        } 
    }
    if(ptc) {
        randomize(pt_arr, pt_arr_size);
        global_queue_tcp = malloc(sizeof(struct queue));
        global_queue_tcp->q = malloc(pt_arr_size * sizeof(struct port *));
        if(global_queue_tcp == NULL) {
            fprintf(stderr,"Chyba pri alokaci pameti.\n");
            exit(1);   
        }
        if(global_queue_tcp->q == NULL) {
            fprintf(stderr,"Chyba pri alokaci pameti.\n");
            exit(1);   
        }
        global_queue_tcp->count = pt_arr_size;
        global_queue_tcp->q = pt_arr;
        global_queue_tcp->front = 0;
        global_queue_tcp->rear = -1;

        global_list_tcp = malloc(pt_arr_size * sizeof(struct port));
        if(global_list_tcp == NULL) {
            fprintf(stderr,"Chyba pri alokaci pameti.\n");
            exit(1);   
        }
        for(int i = 0; i < pt_arr_size; i++) {
            global_list_tcp[i].port = 0;
            global_list_tcp[i].passed = false;
            global_list_tcp[i].count = 0;
            global_list_tcp[i].rst = 0;
        }

        tcp_loop_arg = malloc(sizeof(struct xxp_arguments));
        if(tcp_loop_arg == NULL) {
            fprintf(stderr,"Chyba pri alokaci pameti.\n");
            exit(1);        
        }
        memset(tcp_loop_arg->ifc,'\0',20);
        strcpy(tcp_loop_arg->ifc,addresses[0].ifc);
        memset(tcp_loop_arg->target_address,'\0',16);
        strcpy(tcp_loop_arg->target_address,host);
        tcp_loop_arg->port_count = pt_arr_size;
        tcp_loop_arg->decoy_count = decoy_count;
        tcp_loop_arg->client = client_tcp;
        tcp_loop_arg->min_port = min_port_pt;
        tcp_loop_arg->xxp = true; // true = tcp, false = udp

        if (pthread_create(&tcp_loop, NULL, xxp_looper, (void *)tcp_loop_arg)) {
            fprintf(stderr, "Chyba pri vytvareni vlakna.\n");
            exit(1);
        } 
    }  

    if(puc) {
        pthread_join(udp_loop, NULL);
        free(udp_loop_arg);
    }
    if(ptc) {
        pthread_join(tcp_loop, NULL); 
        free(tcp_loop_arg);
    }

    ///////////////////////////////////////////////////////////
    // TO JE KONEC TOTO
    ///////////////////////////////////////////////////////////

    pcap_close(sniff);
    free(pt_arr);
    free(global_queue_tcp);
    free(global_queue_udp);
    free(interfaces);

    char fake_ip[150];
    memset(fake_ip,'\0',150);
    for(int i = 0; i < decoy_count; i++) { // -1 tu bude pokud je soucasti adres i adr interface
        snprintf(fake_ip,149,"sudo ip addr del %s/24 dev %s",addresses[i].ip, addresses[i].ifc);
        system(fake_ip);
    }
    free(addresses);

    close(client_tcp);
    close(client_udp);

    return 0;
}
