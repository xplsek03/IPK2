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

pthread_mutex_t mutex_queue_remove = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t mutex_queue_size = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t mutex_queue_insert = PTHREAD_MUTEX_INITIALIZER;

struct queue *global_queue;

#define RAND_MAX 2147483647

#ifndef FUNCTIONS_H
#include "functions.h"
#endif
#ifndef PING_H
#include "ping.h"
#endif

int main(int argc, char **argv) {
    srand(time(0)); // zamichej cislama
	// promenne pro validaci argumentu
    char *pu;
    char *pt;
    char *host;
    int puc = 0;
    int ptc = 0;
    int hc = 0;
    
    // pole pro seznam 
    // struct port *pu_arr;
    struct port *pt_arr;
    
    // kontrola poctu argumentu
    if(argc != 6) {
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
        else {
            host = argv[i];
            hc++;
        }
    }

    // validace nalezenych argumentu
    if(puc != 1 || ptc != 1 || hc != 1) {
        fprintf(stderr,"Spatne zadane argumenty programu.\n");
        return 1;
    }

    // co jsou oba argumenty zac, jestli range, vycet..
    int ret_pu = checkArg(pu);
    int ret_pt = checkArg(pt);
    if(!ret_pu || !ret_pt) {
        fprintf(stderr,"Spatne zadane argumenty programu.\n");
        return 1;
    }

    // celkovy pocet portu
    //int pu_arr_size = 0;
    int pt_arr_size = 0;
    int min_port;

    // kontrola argumentu pu a pt
    //processArgument(ret_pt, &pt_arr, &pt_arr_size, pt);
    //processArgument(ret_pu, pu_arr, &pu_arr_size, pu);

    // vyjebany argumenty a malloc 

    int size = 0;

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
        min_port = pt_arr_subst[0].port;
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
        min_port = pt_arr[0].port;
    }

    for(int i = 0; i < size; i++) {
        if(pt_arr[i].port > 65535 || pt_arr[i].port < 0) {
            fprintf(stderr,"Spatny rozsah cisla portu (0 - 65535).\n");
            exit(1);
        }
    }

    // zpracuj hosta => target
    struct hostent *hname;
	struct sockaddr_in target;
    if ((hname = gethostbyname(host)) == NULL) {
        fprintf(stderr,"Nelze prevest host na ip.\n");
        exit(1);
    }
    memcpy(&target.sin_addr, hname->h_addr_list[0], hname->h_length);
    target.sin_family = AF_INET;
    target.sin_port = htons(1337);

    // zalozeni TCP socketu
    int client = socket(AF_INET, SOCK_RAW, IPPROTO_TCP); // SOCKET POUZE NA TCP
    if (client < 0)  
        fprintf(stderr,"Chyba pri vytvareni socketu.\n"); 

    // inicializace seznamu interfaces pro ping
    int interfaces_count = 0; // kolik existuje rozhrani ( - 1)
    struct single_interface *interfaces = getInterface(&interfaces_count);

    bool ping_succ = false; // jestli byl kazdy z pingu ok

    struct single_address *addresses = malloc(sizeof(struct single_address)*DECOYS); // pole decoy ip adres
    if(addresses == NULL) {
        fprintf(stderr,"Chyba pri alokaci.\n");
        return 1;
    }

    int decoy_count = 0; // pocet ip adres
    int passed_interfaces = 0; // 0..1..2: snizuje se pocet pouzitych decoy adres z kazdeho dalsiho rozhrani

    for(int i = 0; i < interfaces_count; i++) {
        ping_succ = false; // promenna jestli byl ping ok, meneno z libpcap handleru

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
        ping_arg->client = client;
        ping_arg->ok = &ping_succ;
        ping_arg->target_struct = &target;


        if(ping(ping_arg)) { // ping prosel
            passed_interfaces++; // pocet rozhrani co prosly
            interfaces[i].usable = true; // rozhrani se da dal pouzivat, protoze se z nej da dosahnout na target
            generate_decoy_ips(interfaces[i], &passed_interfaces, addresses, &decoy_count, client, host, &target);
            continue; // uz dal nepinguj z tohohle rozhrani
        }

        //free(ping_arg->target_struct);
        //free(ping_arg->ok);
        //free(ping_arg);

    }

    // zpracovani pole decoy adres
    if(passed_interfaces > 0) {
        char arp_item[150];
        char mac[18];
        memset(mac,'\0',18);
        memset(arp_item,'\0',150);
        for(int i = 0; i < decoy_count; i++) {
            get_mac(mac, addresses[i].ifc);
            snprintf(arp_item,149,"sudo arp -s %s %s",addresses[i].ip, mac);
            system(arp_item);
        }

        // dopln seznam adres o adresy rozhrani
        if((DECOYS - decoy_count < interfaces_count + 1) || (DECOYS > decoy_count + 1 + interfaces_count))
            addresses = realloc(addresses, sizeof(struct single_address)*(interfaces_count+1+decoy_count));

        for(int i = 0; i < interfaces_count; i++) {
            if(interfaces[i].usable) {
                memset(&addresses[decoy_count].ip,'\0',16);
                strcpy(addresses[decoy_count].ip,interfaces[i].ip);
                memset(&addresses[decoy_count].ifc,'\0',20);
                strcpy(addresses[decoy_count].ifc,interfaces[i].name);
                decoy_count++;
            }
        }
    }
    else {
        fprintf(stderr,"Host neexistuje nebo je nedostupny.\n");
        return 1;
    }

    printf("--ADRESY--\n");
    for(int i = 0; i < decoy_count; i++)
        printf("%s %s\n",addresses[i].ip,addresses[i].ifc);

    // https://stackoverflow.com/questions/6127503/shuffle-array-in-c

    randomize(pt_arr, pt_arr_size);

    global_queue = malloc(sizeof(struct queue));
    global_queue->q = malloc(pt_arr_size * sizeof(struct port *));
    if(global_queue == NULL) {
        fprintf(stderr,"Chyba pri alokaci pameti.\n");
        exit(1);   
    }
    if(global_queue->q == NULL) {
        fprintf(stderr,"Chyba pri alokaci pameti.\n");
        exit(1);   
    }
    global_queue->count = pt_arr_size;
    global_queue->q = pt_arr;
    global_queue->front = 0;
    global_queue->rear = -1;

    printf("--GLOBAL QUEUE--\n");
    for(int i = 0; i < pt_arr_size; i++)
        printf("%i\n",global_queue->q[i].port);

    ///////////////////////////////////////////////////////////
    // INTERFACES A PARALELNI ZPRACOVANI NA KAZDEM INTERFACE //
    ///////////////////////////////////////////////////////////

    // vytvoreni vlaken interface. struktura: single_ifc-> 1 sniffer + x domen
    pthread_t single_interface[passed_interfaces]; // vytvor pro kazde interface jedno vlakno
    void *retval[passed_interfaces];
    int c = 0; // interni citac vlaken snifferu portu

    for(int i = 0; i < interfaces_count; i++) {
        if(interfaces[i].usable) {

            // argumenty single_ifc->port snifferu + domain
            struct interface_arguments *interface_loop_arg = malloc(sizeof(struct interface_arguments));
            interface_loop_arg->addresses = malloc(DECOYS * sizeof(struct single_address *));
            if(interface_loop_arg == NULL) {
                fprintf(stderr,"Chyba pri alokaci pameti.\n");
                exit(1);        
            }
            if(interface_loop_arg->addresses == NULL) {
                fprintf(stderr,"Chyba pri alokaci pameti.\n");
                exit(1);        
            }
            memset(interface_loop_arg->ifc,'\0',20);
            strcpy(interface_loop_arg->ifc,interfaces[i].name);
            memset(interface_loop_arg->target_address,'\0',16);
            strcpy(interface_loop_arg->target_address,host);
            interface_loop_arg->pt_arr_size = pt_arr_size;
            interface_loop_arg->addresses = addresses;
            interface_loop_arg->decoy_count = decoy_count;
            interface_loop_arg->client = client;
            interface_loop_arg->min_port = min_port;

            if (pthread_create(&single_interface[c++], NULL, interface_looper, (void *)interface_loop_arg)) {
                fprintf(stderr, "Chyba pri vytvareni vlakna.\n");
                exit(1);
            }  
        }      
    }

    for(int i = 0; i < c; i++) {
        pthread_join(single_interface[i], &retval[i]); // pockej az dojedou vsechna vlakna
    }

    // vymaz po sobe arp zaznamy
    if(passed_interfaces > 0) {
        char arp_item_del[150];
        memset(arp_item_del,'\0',150);
        for(int i = 0; i < decoy_count; i++) {
            snprintf(arp_item_del,149,"sudo arp -d %s",addresses[i].ip);
            system(arp_item_del);
        }
    }

    free(pt_arr);
    free(global_queue);
    free(interfaces);
    free(addresses);
    return 0;

}
