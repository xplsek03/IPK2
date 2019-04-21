#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ether.h>
#include <pcap.h>
#include <ifaddrs.h>
#include <ctype.h>
#include <netdb.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <limits.h>
#include <stdbool.h>
#include <errno.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

unsigned short rndmstr(unsigned short lower, unsigned short upper)
{
    return (rand() % (upper - lower + 1)) + lower;
}

int main() {

    time_t t;
    srand(time(&t));
    struct ifreq ifr = {0};
    int s;
    char mac[18];
    time_t rtime;
    char val[16] = "0123456789abcdef";

    srand(time(&rtime)); 
    sprintf(mac,"%0a:23:%c%c:%c%c:%c%c:%c%c",val[rndmstr(0,15)],val[rndmstr(0,15)],val[rndmstr(0,15)],val[rndmstr(0,15)],val[rndmstr(0,15)],val[rndmstr(0,15)],val[rndmstr(0,15)],val[rndmstr(0,15)]);
    sscanf(mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &ifr.ifr_hwaddr.sa_data[0], &ifr.ifr_hwaddr.sa_data[1],
    &ifr.ifr_hwaddr.sa_data[2], &ifr.ifr_hwaddr.sa_data[3], &ifr.ifr_hwaddr.sa_data[4], &ifr.ifr_hwaddr.sa_data[5]);
 
    s = socket(AF_INET, SOCK_DGRAM, 0);
    if(s == -1) {
        //fprintf(stderr,"Mac adresu neslo zmenit.\n");
    } 
    strcpy(ifr.ifr_name, "wlan0");
    ifr.ifr_hwaddr.sa_family = ARPHRD_ETHER;
    if(ioctl(s, SIOCSIFHWADDR, &ifr) == -1)
        printf("* mac: not changed\n");
    else
        printf("* new mac: %s\n",mac);

return 0; 
}