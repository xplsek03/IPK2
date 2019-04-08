// struktury a CRC, prevzato z https://www.tenouk.com/Module43a.html

#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h> // sleep()
#include <pthread.h>
#include <getopt.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/types.h>
#include <stdbool.h>

#define DECOYS 20
#define PCKT_LEN 8192
#define PORT_RANGE_START 50000
#define PORT_RANGE_END 60000

unsigned short csum(unsigned short *buf, int len);
void *send_syn(void *arg);
int portCount(int type, int *arr);
void *sniffer(void *arg, char *ifc);
struct single_interface **getInterface(int *interfaces_count);
int generate_decoy_ips(struct single_interface interface, int *passed_interfaces, char **addresses, int *decoy_count, int client, char *target);