// struktury a CRC, prevzato z https://www.tenouk.com/Module43a.html

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <stdbool.h>
#include <sys/time.h>
#include <pcap.h>

#define DECOYS 6 // pouze suda cisla!
#define PCKT_LEN 512
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
bool queue_isEmpty(int count);
bool queue_isFull(int count, int max);
int queue_size(int count);
void queue_insert(struct port data, int *rear, int max, struct port *q, int *count);
struct port queue_removeData(struct port *q, int *front, int max, int *count);

struct port {   
    int count; // kolikrat uz prosel zkousenim
    struct timeval time; // jak je stary
    bool passed; // pustit ho pryc, protoze repsondoval syn ack?
    int port; // port je tu kvuli uvodni fronte
    int rst; // kolikrat dosel signal reset? Je skutecne uzavreny?
};

struct single_address {
    char ifc[10];
    char ip[16];
    unsigned short cider;
};

typedef char local_address[16];

struct xxp_arguments {
    char ifc[10];
    int client;
    int decoy_count;
    char target_address[16];
    int min_port;
    int port_count;
};

struct xxp_sniffer_arguments {
    char ifc[10];
    char target[16];
    bool *end_of_evangelion;
    int min_port;
    int port_count;
    int decoy_count;
};

struct obo_sniffer_arguments {
    char ifc[10];
    char target[16];
    bool *end_of_evangelion;
    int decoy_count;
    bool *response_received;
};

struct xxp_handler_arguments {
    bool *xxp_killer;
    int port_count;
    int *local_counter;
};

struct single_interface {
    char name[10];
    char ip[16];
    char mask[16];
    bool usable;
};

struct xxp_callback_arguments {
    char target[16];
    bool *end_of_evangelion;
    pcap_t *sniff;
    int min_port;
    int port_count;
    int decoy_count;
};

struct obo_callback_arguments {
    char target[16];
    bool *end_of_evangelion;
    bool *response_received;
    pcap_t *sniff;
    int decoy_count;
};

struct domain_arguments {
        int client;
        char target_address[16]; 
        char ip[16];
        bool *end_of_evangelion;
        int min_port;
        int *local_counter;
        int port_count;
        char ifc[10];
};

struct pseudoTCPPacket {
  uint32_t srcAddr;
  uint32_t dstAddr;
  uint8_t zero;
  uint8_t protocol;
  uint16_t TCP_len;
};

struct pseudoUDPPacket {
  uint32_t srcAddr;
  uint32_t dstAddr;
  uint8_t zero;
  uint8_t protocol;
  uint16_t UDP_len;
};

unsigned short in_cksum_tcp(int src, int dst, unsigned short *addr, int len);
int rndm(int lower, int upper);
void send_syn(int spoofed_port, int target_port, char *spoofed_address, char *target_address, int client);
void send_udp(int spoofed_port, int target_port, char *spoofed_address, char *target_address, int client);
void *xxp_sniffer(void *arg);
void *obo_sniffer(void *arg);
struct single_interface *getInterface(int *interfaces_count);
void generate_decoy_ips(struct single_interface interface, int *passed_interfaces, struct single_address *addresses, int *decoy_count, char *target, struct sockaddr_in *target_struct);
void *xxp_looper(void* arg);
void *obo_looper(void *arg);
void *xxp_handler(void* arg);
void *domain_loop(void *arg);
void xxp_callback(struct xxp_callback_arguments *arg, const struct pcap_pkthdr *header, const unsigned char *packet);
void obo_callback(struct obo_callback_arguments *arg, const struct pcap_pkthdr *header, const unsigned char *packet);
void processArgument(int ret_px, struct port **px_arr, int *px_arr_size, char *px);
int getCharCount(char *str, char z);
int checkArg(char *argument);
unsigned short csum(unsigned short *ptr,int nbytes);
void randomize(struct port *array, int n);
void get_mac(char *mac, char *dev);
void change_mac(char *dev);
unsigned long rndmsleep(unsigned long lower, unsigned long upper);
unsigned short rndmstr(unsigned short lower, unsigned short upper);
unsigned short cidr(char* ipAddress);