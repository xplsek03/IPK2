// struktury a CRC, prevzato z https://www.tenouk.com/Module43a.html

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <stdbool.h>
#include <sys/time.h>
#include <pcap.h>

#define DECOYS 2
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
    char ifc[20];
    char ip[16];
    unsigned short cidr;
};

typedef char local_address[16];

struct interface_arguments {
    char ifc[20];
    int client;
    struct single_address *addresses;
    int decoy_count;
    char target_address[16];
    int pt_arr_size;
    int min_port;
};

struct interface_sniffer_arguments {
    char ifc[20];
    char target[16];
    bool *end_of_evangelion;
    local_address local_addresses[DECOYS+1];
    int local_address_counter;
    int pt_arr_size;
    struct port **local_list;
    int min_port;
};

struct interface_handler_arguments {
    struct port **local_list;
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
    local_address local_addresses[DECOYS+1];
    int local_address_counter;
    struct port **local_list;
    int min_port;
};

struct domain_arguments {
        int client;
        char target_address[16]; 
        char ip[16];
        int pt_arr_size;
        struct port **local_list;
        int *local_list_counter;
        bool *end_of_evangelion;
        int min_port;
};

struct pseudoTCPPacket {
  uint32_t srcAddr;
  uint32_t dstAddr;
  uint8_t zero;
  uint8_t protocol;
  uint16_t TCP_len;
};

unsigned short in_cksum_tcp(int src, int dst, unsigned short *addr, int len);
int rndm(int lower, int upper);
void send_syn(int spoofed_port, int target_port, char *spoofed_address, char *target_address, int client);
void *interface_sniffer(void *arg);
struct single_interface *getInterface(int *interfaces_count);
void generate_decoy_ips(struct single_interface interface, int *passed_interfaces, struct single_address *addresses, int *decoy_count, int client, char *target, struct sockaddr_in *target_struct);
void *interface_looper(void* arg);
void *interface_handler(void* arg);
void *domain_loop(void *arg);
void interface_callback(struct interface_callback_arguments *arg, const struct pcap_pkthdr *header, const unsigned char *packet);
void processArgument(int ret_px, struct port **px_arr, int *px_arr_size, char *px);
int getCharCount(char *str, char z);
int checkArg(char *argument);
unsigned short csum(unsigned short *ptr,int nbytes);
void randomize(struct port *array, int n);
void *get_mac(char *mac, char *dev);
unsigned long rndmsleep(unsigned long lower, unsigned long upper);
unsigned short rndmstr(unsigned short lower, unsigned short upper);
static unsigned short cidr(char* ipAddress);