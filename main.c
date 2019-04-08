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

#include "functions.h"

int checkArg(char *argument) {
    int range = 0; // -
    int col = 0; // ,
    for(int i = 0; i < strlen(argument); i++) {
        if(isdigit(argument[i]))
            continue;
        else if(argument[i] == '-')
            range++;
        else if(argument[i] == ',')
            col++;
        else
            return 0;       
    } 
    if(range > 1 || !isdigit(argument[strlen(argument)]) || (range > 0 && col > 0))
        return 0;
    
    if(range > 1) {
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

int processArgument(char *argument,int ret, int *xu_arr) { // BUG zkontrolu jaby tam nebyly nahodou dva stejne porty
    if(ret == 1) { // hledas -
        xu_arr = malloc(sizeof(int)*2);
        if(xu_arr == NULL)
            return 2; // malloc error
        int i = 0;
        char *end;
        char *p = strtok(argument, "-");
        while (p != NULL) {
            xu_arr[i++] = (int)strtol(p, &end, 10);
            p = strtok(NULL, "-");
        }
    }
    else if(ret == 2) { // hledas ,
        int l = getCharCount(argument,',');
        xu_arr = malloc(sizeof(int) * (l+1));
        if(xu_arr == NULL)
            return 2; // malloc error
        int i = 0;
        char *end;
        char *p = strtok(argument, ",");
        while (p != NULL) {
            xu_arr[i++] = (int)strtol(p, &end, 10);
            p = strtok(NULL, ",");
        }
    }
    else { // vkladas cely cislo do pole
        xu_arr = malloc(sizeof(int));
        char *end;
        if(xu_arr == NULL)
            return 2; // malloc error
        xu_arr[0] = (int)strtol(argument, &end, 10);
    }

    int size = sizeof(xu_arr)/sizeof(int);
    for(int i = 0; i < size; i++) {
        if(xu_arr[i] > 65535 || xu_arr[i] < 0)
            return 1; // chyba rozsahu int
    }
    return 0;
}

int main(char **argv, int argc) {

	// promenne pro vlaidaci argumentu
    char *pu = "";
    char *pt = "";
    char *host = "";
    bool foundPu = false;
    bool foundPt = false;
    bool foundHost = false;
    int puc = 0;
    int ptc = 0;
    int hc = 0;
    
    // pole pro seznam 
    int *pu_arr;
    int *pt_arr;
    
    // kontrola poctu argumentu
    if(argc != 6)
        goto wrong_arguments;

    // nalezeni argumentu
    for(int i = 1; i < argc; i++) {
        if(foundPu) {
            pu = argv[i];
            puc++;
            continue;
        }
        if(foundPt) {
            pt = argv[i];
            ptc++;
            continue;
        }
        if(argv[i] == "-pu") {
            if(i == argc-1)
                goto wrong_arguments;
            else {
                foundPu = true;
            }
        }
        if(argv[i] == "-pt") {
            if(i == argc-1)
                goto wrong_arguments;
            else
                foundPt = true;
        }
        else {
            host = argv[i];
            foundHost = true;
            hc++;
        }
    }

    // validace nalezenych argumentu
    if(puc != 1 || ptc != 1 || hc != 1)
        goto wrong_arguments;

    // co jsou oba argumenty zac, jestli range, vycet..
    int ret_pu = checkArg(pu);
    int ret_pt = checkArg(pt);
    if(!ret_pu || !ret_pt)
        goto wrong_arguments;

    int ret_pu2 = processArgument(pu,ret_pu,pu_arr);
    int ret_pt2 = processArgument(pt,ret_pt,pt_arr);   
    if(ret_pu2 == 2 || ret_pt2 == 2)
        goto malloc_error;
    if(ret_pu2 == 1 || ret_pt2 == 1)
        goto range_error;

	int pu_arr_size = portCount(ret_pu, pu_arr);
	int pt_arr_size = portCount(ret_pt, pt_arr);

    // pokud tam byla pomlcka, preved to na pole. BUG: dodelat i pro UDP, nejspis dat do funkce
    if(ret_pt == 1) {
        int *new_pt_arr = malloc(sizeof(int) * pt_arr_size);
        if(new_pt_arr == NULL)
            goto malloc_error;
        for(int i = 0; i < pt_arr_size; i++)
            new_pt_arr[i] = pt_arr[0] + i;
        free(pt_arr);
        pt_arr = new_pt_arr;
    }
    // ted jsou v pu_arr a pt_arr jednotlive porty, a v ret_pu a ret_pt je typ pole (1'-' 2',' 3'int'), pu_arr_size, pt_arr_size jsou velikosti
    
    char *addresses[10] = {"192.168.1.5","192.168.1.6",
                        "192.168.1.50","192.168.1.53",
                        "192.168.1.67","192.168.1.46",
                        "192.168.1.23","192.168.1.105",
                        "192.168.1.25","192.168.1.77"
    }; // napln pole ip adresama, zjisti ktere se daji pouzit uz na zacatku + vytvor ARP zaznam na tomhle hostovi
    int address_count = 10; // pocet ip adres

    // zalozeni socketu
    int client = socket(PF_INET, SOCK_RAW, IPPROTO_TCP); // jeden socket pro praci vice vlaken
    if (client < 0) 
        fprintf(stderr,"Chyba pri vytvareni socketu.\n"); 

    // inicializace seznamu interfaces pro ping
    int interfaces_count = 0; // kolik existuje rozhrani
    struct single_interface **interfaces = getInterface(&interfaces_count);

    pthread_t interface_loop; // thread ID
    bool ping_succ = false; // jestli byl kazdy z pingu ok
    int repeated_ping = 0; // opakovany ping v pripade selhani, tri pokusy
    int some_ping_succ = false; // alespon jeden ping z jakehokoliv rozhrani uspel

    for(int i = 0; i < interfaces_count; i++) {

        ping_succ = false; // promenna jestli byl ping ok, meneno z libpcap handleru

        // vytvor argumenty pingu
        struct ping_arguments *ping_arg = malloc(sizeof(struct ping_arguments));
        if(ping_arg == NULL)
            goto malloc_error;
        ping_arg->client = client;
        ping_arg->target = host;
        ping_arg->ip = interfaces[i]->ip;
        ping_arg->ok = &ping_succ;
        ping_arg->ifc = interfaces[i]->name;

        // spust vlakno s pingem
        while(repeated_ping < 2 || !ping_succ) {

            if (pthread_create(&interface_loop, NULL, ping, &ping_arg)) {
                fprintf(stderr, "Chyba pri vytvareni vlakna.\n");
                exit(1);
            }
            pthread_join(interface_loop, NULL); // pockej nez dojede jeden ping
            pthread_detach(interface_loop); // ukonci vlakno a jed znovu

            if(ping_succ) { // ping prosel
                interfaces[i]->usable = true; // rozhrani se da dal pouzivat, protoze se z nej da dosahnout na target
                some_ping_succ = true; // jeno rozhrani proslo
                // vem adresu a masku a napinguj si dostatek volnych ip do "addresses"
                // vytvor arp zaznam pro tyto nove adresy
                // vyber si jedno rozhrani a uloz do "dev", pak na nem spust sniffer vlakno
                // pokud neni dostupny target z niceho tak vyhod chybu
                break;  
            }
            else { // tri pokusy
                repeated_ping++;
                sleep(1); // pockej jednu sekundu na dalsi ping
            }

        }

        // tohle by slo asi udelat misto smycky zaraz, ale mohly by se tam mlatit libpcap vysledky pingu. mozna na konci

    }

    if(!some_ping_succ) // target nejde pingnout z zadneho interface
        goto host_error;

    // tady spust sniffer vlakno

    //if (pthread_create(&tid, NULL, sniffer, NULL)) {
	//	fprintf(stderr, "Chyba pri vytvareni vlakna.\n");
	//	exit(1);
	//}

    // tohle zabal do funkce pro udp i pro tcp
    int target_ports_count = pt_arr_size;
    pthread_t single_port; // vlakno pro jednotlivy port

    for(int i = 0; i < target_ports_count; i++) {
        for(int spoofed_port = PORT_RANGE_START; spoofed_port < PORT_RANGE_END; spoofed_port++) {
            
            // struktura = argument threadovane funkce
            struct thread_arguments *arg = malloc(sizeof(struct thread_arguments));
            if(arg == NULL)
                goto malloc_error;
            arg->client = client;
            arg->target_port = pt_arr[i]; 
            arg->target_address = host; 
            arg->addresses = addresses;
            arg->address_count = address_count; 
            arg->spoofed_port = spoofed_port;

            if(pthread_create(&single_port, NULL, send_syn, &arg)) {
                fprintf(stderr,"Chyba pri vytvareni vlakna.\n");
                exit(1);
            }
        }
    }
    
    wrong_arguments:
        fprintf(stderr,"Spatne zadane argumenty programu.\n");
        return 1;

    malloc_error:
        fprintf(stderr,"Chyba pri alokaci.\n");
        return 1;

    range_error:
        fprintf(stderr,"Spatny rozsah cisla portu (0 - 65535).\n");
        return 1;

    host_error:
        fprintf(stderr,"Host neexistuje nebo je nedostupny.\n");
        return 1;

}
