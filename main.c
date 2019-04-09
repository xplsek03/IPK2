#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h> // sleep()
#include <pthread.h>
#include <getopt.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <stdbool.h>
#include <ctype.h>

#ifndef FUNCTIONS_H
#include "functions.h"
#endif
#ifndef PING_H
#include "ping.h"
#endif

int main(int argc, char **argv) {

    srand(time(0)); // random

	// promenne pro vlaidaci argumentu
    char *pu = "";
    char *pt = "";
    char *host = "";
    int puc = 0;
    int ptc = 0;
    int hc = 0;
    
    // pole pro seznam 
    int *pu_arr;
    int *pt_arr;
    
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
        printf("?? %i %i\n",ret_pu,ret_pt);
        fprintf(stderr,"Spatne zadane argumenty programu.\n");
        return 1;
    }

    int ret_pu2 = processArgument(pu,ret_pu,&pu_arr);
    int ret_pt2 = processArgument(pt,ret_pt,&pt_arr);   
    if(ret_pu2 == 2 || ret_pt2 == 2) {
        fprintf(stderr,"Chyba pri alokaci.\n");
        return 1;
    }

    if(ret_pu2 == 1 || ret_pt2 == 1) {
        fprintf(stderr,"Spatny rozsah cisla portu (0 - 65535).\n");
        return 1;
    }

	int pu_arr_size = portCount(ret_pu, pu_arr);
	int pt_arr_size = portCount(ret_pt, pt_arr);

    // pokud tam byla pomlcka, preved to na pole. BUG: dodelat i pro UDP, nejspis dat do funkce
    if(ret_pt == 1) {
        int *new_pt_arr = malloc(sizeof(int) * pt_arr_size);
        if(new_pt_arr == NULL) {
            fprintf(stderr,"Chyba pri alokaci.\n");
            return 1;
        }
        for(int i = 0; i < pt_arr_size; i++)
            new_pt_arr[i] = pt_arr[0] + i;
        free(pt_arr);
        pt_arr = new_pt_arr;
    }

    // zalozeni socketu

    //int client = socket(PF_INET, SOCK_RAW, IPPROTO_TCP); // jeden socket pro praci vice vlaken
    //if (client < 0) 
        //fprintf(stderr,"Chyba pri vytvareni socketu.\n"); 
    int client = 25;

    // inicializace seznamu interfaces pro ping
    int interfaces_count = 0; // kolik existuje rozhrani ( - 1)
    struct single_interface *interfaces = getInterface(&interfaces_count);

    bool ping_succ = false; // jestli byl kazdy z pingu ok
    int repeated_ping = 0; // opakovany ping v pripade selhani, tri pokusy

    struct single_address *addresses = malloc((sizeof(char)*36+sizeof(struct single_address))*DECOYS); // pole decoy ip adres
    if(addresses == NULL) {
        fprintf(stderr,"Chyba pri alokaci.\n");
        return 1;
    }

    int decoy_count = 0; // pocet ip adres
    int passed_interfaces = 0; // 0..1..2: snizuje se pocet pouzitych decoy adres z kazdeho dalsiho rozhrani

    for(int i = 0; i < interfaces_count; i++) {

        ping_succ = false; // promenna jestli byl ping ok, meneno z libpcap handleru

        // spust vlakno s pingem
        while(repeated_ping < 2 || !ping_succ) {

            // vyrob plibcap capture filter
            char phrase[14+strlen(interfaces[i].ip)+strlen(host)];
            memset(phrase,'\0',14+strlen(interfaces[i].ip)+strlen(host));
            strcat(phrase, "dst ");
            strcat(phrase, interfaces[i].ip);
            strcat(phrase, " and src ");
            strcat(phrase, host);
            phrase[14+strlen(interfaces[i].ip)+strlen(host)-1] = '\0';

            ping(client, host, interfaces[i].ip, &ping_succ, interfaces[i].name, phrase);

            if(ping_succ) { // ping prosel
                passed_interfaces++; // pocet rozhrani co prosly
                interfaces[i].usable = true; // rozhrani se da dal pouzivat, protoze se z nej da dosahnout na target
                generate_decoy_ips(interfaces[i], &passed_interfaces, &addresses, &decoy_count, client, host);
                break; // uz dal nepinguj z tohohle rozhrani
            }
            else { // tri pokusy
                repeated_ping++;
                sleep(1); // pockej jednu sekundu na dalsi ping
            }
        }

        // BUG: tohle by slo asi udelat misto smycky zaraz, ale mohly by se tam mlatit libpcap vysledky pingu. mozna na konci
    }

    printf("DECOYS\n");

    // zpracovani pole decoy adres
    if(passed_interfaces > 0) {
        char arp_item[50];
        for(int i = 0; i < decoy_count; i) {
            strcat(arp_item, "sudo arp -s ");
            strcat(arp_item, addresses[i].ip);
            strcat(arp_item, " -D ");
            strcat(arp_item, addresses[i].ifc);
            arp_item[12+strlen(addresses[i].ip)+strlen(addresses[i].ifc)+5-1] = '\0';
            system(arp_item);
        }
        
        // dopln seznam adres o adresy rozhrani
        if((DECOYS - decoy_count < interfaces_count + 1) || (DECOYS > decoy_count + 1 + interfaces_count))
            addresses = realloc(addresses, sizeof(struct single_address)*(interfaces_count+1+decoy_count));

        for(int i = 0; i < interfaces_count+1; i++) {
            if(interfaces[i].usable) {
                addresses[decoy_count].ip = interfaces[i].ip;
                addresses[decoy_count].ifc = interfaces[i].name;
                decoy_count++;
            }
        }
    }
    else {
        fprintf(stderr,"Host neexistuje nebo je nedostupny.\n");
        return 1;
    }

    // vytvoreni vlaken interface. struktura: single_ifc-> 1 sniffer + x domen
    pthread_t single_interface[passed_interfaces]; // vytvor pro kazde interface jedno vlakno
    void *retval[passed_interfaces];
    int c = 0; // interni citac vlaken snifferu portu

    for(int i = 0; i < interfaces_count; i++) {
        if(interfaces[i].usable) {

            // argumenty single_ifc->port snifferu + domain
            struct interface_arguments *interface_loop_arg = malloc(sizeof(struct interface_arguments));
            if(interface_loop_arg == NULL) {
                fprintf(stderr,"Chyba pri alokaci pameti.\n");
                exit(1);        
            }
            // vyrob plibcap capture filter, ktery zachyti SYN / RST / ICMP special
            char phrase[10+strlen(interfaces[i].ip)+strlen(host)];
            strcat(phrase, "xxx");
            strcat(phrase, interfaces[i].ip);
            strcat(phrase, " xxx ");
            strcat(phrase, host);
            phrase[10+strlen(interfaces[i].ip)+strlen(host)-1] = '\0'; // BUG: dodelej

            interface_loop_arg->pt_arr_size = pt_arr_size;
            interface_loop_arg->addresses = addresses;
            interface_loop_arg->decoy_count = decoy_count;
            interface_loop_arg->filter = phrase;
            interface_loop_arg->client = client;
            interface_loop_arg->ifc = interfaces[i].name;
            interface_loop_arg->target_address = host;
            interface_loop_arg->pt_arr = pt_arr;

            if (pthread_create(&single_interface[c++], NULL, interface_looper, (void *)interface_loop_arg)) {
                fprintf(stderr, "Chyba pri vytvareni vlakna.\n");
                exit(1);
            }  
        }      
    }

    for(int i = 0; i < c; i++) {
        pthread_join(single_interface[i], &retval[i]); // pockej az dojedou vsechna vlakna
    }

    free(addresses);
    return 0;

}
