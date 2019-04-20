#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if_arp.h>
#include <net/if.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <time.h>

int main() {

    struct ifreq ifr = {0};
    int s;
    char mac[18];
    srand(time(0)); 
    sprintf(mac,"88:%s%X:%s%X:%s%X:%s%X:%s%X", (rand() % 256) < 16 ? "0" : "", (rand() % 256),(rand() % 256) < 16 ? "0" : "", (rand() % 256),(rand() % 256) < 16 ? "0" : "", (rand() % 256),(rand() % 256) < 16 ? "0" : "", (rand() % 256),(rand() % 256) < 16 ? "0" : "", (rand() % 256));
 
    sscanf(mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &ifr.ifr_hwaddr.sa_data[0], &ifr.ifr_hwaddr.sa_data[1],
    &ifr.ifr_hwaddr.sa_data[2], &ifr.ifr_hwaddr.sa_data[3], &ifr.ifr_hwaddr.sa_data[4], &ifr.ifr_hwaddr.sa_data[5]);
 
    s = socket(AF_INET, SOCK_DGRAM, 0);
    if(s == -1) {
        fprintf(stderr,"Mac adresu neslo zmenit.\n");
        return;
    } 
    strcpy(ifr.ifr_name, "eth0");
    ifr.ifr_hwaddr.sa_family = ARPHRD_ETHER;
    if(ioctl(s, SIOCSIFHWADDR, &ifr) == -1)
        fprintf(stderr,"Mac adresu neslo zmenit.\n");
    return 0;

}