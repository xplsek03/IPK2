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
#include <sys/types.h>
#include <stdbool.h>
#include <sys/time.h>
#include <pcap.h>

#define DECOYS 4
#define PCKT_LEN 8192
#define PORT_RANGE_START 50000
#define PORT_RANGE_END 60000

// globalni fronta portu
struct queue {
    struct port *q;
    int front;
    int rear;
    int count;
};

// funkce globalni fronty
struct port queue_peek(struct port *q, int front);
bool queue_isEmpty(int count);
bool queue_isFull(int count, int max);
int queue_size(int count);
void queue_insert(struct port data, int rear, int max, struct port *q, int count);
struct port queue_removeData(struct port *q, int front, int max, int count);

// zaznam v port queue (a seznamu na kazdem interface)
// port je urcenej poradim v listu, tzn list[i], kde i: 1 - 65535
struct port {   
    int count; // kolikrat uz prosel zkousenim
    struct timeval time; // jak je stary
    bool passed; // pustit ho pryc, protoze repsondoval syn ack?
    int port; // port je tu kvuli uvodni fronte
    int rst; // kolikrat dosel signal reset? Je skutecne uzavreny?
};

struct single_address {
    char ifc[20];
    char ip[16];
};

typedef char local_address[16];

struct interface_arguments {
    char ifc[20];
    int client;
    struct single_address *addresses;
    int decoy_count;
    char target_address[16];
    int pt_arr_size;
    struct queue *global_queue;
};

struct interface_sniffer_arguments {
    char ifc[20];
    char target[16];
    bool *end_of_evangelion;
    local_address local_addresses[DECOYS];
    int local_address_counter;
};

struct interface_handler_arguments {
    struct queue *global_queue;
    struct port *local_list;
    bool *interface_killer;
    int *local_list_counter;
    int pt_arr_size;
};

struct single_interface {
    char name[20];
    char ip[16];
    char mask[16];
    bool usable;
};

struct interface_callback_arguments {
    char target[16];
    bool *end_of_evangelion;
    pcap_t *sniff;
    local_address local_addresses[DECOYS];
    int local_address_counter;
};

struct domain_arguments {
        int client;
        char target_address[16]; 
        char ip[16];
        int pt_arr_size;
        int *pt_arr;
        struct queue *global_queue;
        struct port *local_list;
        int *local_list_counter;
        pthread_mutex_t *mutex_queue_insert;
        pthread_mutex_t *mutex_queue_remove;
        pthread_mutex_t *mutex_queue_size;
};


struct tcpheader {
    unsigned short int tcph_srcport;
    unsigned short int tcph_destport;
    unsigned int       tcph_seqnum;
    unsigned int       tcph_acknum;
    unsigned char      tcph_reserved:4, tcph_offset:4;
    // unsigned char tcph_flags;
    unsigned int
        tcp_res1:4,     
        tcph_hlen:4,    
        tcph_fin:1,      
        tcph_syn:1,       
        tcph_rst:1,      
        tcph_psh:1,     
        tcph_ack:1,      
        tcph_urg:1,    
        tcph_res2:2;
    unsigned short int tcph_win;
    unsigned short int tcph_chksum;
    unsigned short int tcph_urgptr;
};

int rndm(int lower, int upper);
void send_syn(int spoofed_port, int target_port, char *spoofed_address, char *target_address, int client);
void *interface_sniffer(void *arg);
struct single_interface *getInterface(int *interfaces_count);
void generate_decoy_ips(struct single_interface interface, int *passed_interfaces, struct single_address *addresses, int *decoy_count, int client, char *target, struct sockaddr_in *target_struct);
void *interface_looper(void* arg);
void *interface_handler(void* arg);
void *domain_loop(void *arg);
void interface_callback(struct interface_callback_arguments *arg, const struct pcap_pkthdr *header, const unsigned char *packet);
int processArgument(char *argument,int ret, struct port *xu_arr);
int getCharCount(char *str, char z);
int checkArg(char *argument);
unsigned short csum(unsigned short *buf, int len);
void randomize(struct port *array, int n);
void *get_mac(char *mac, char *dev);