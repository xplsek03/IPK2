#define PCKT_LEN 512 // 8192
#define PACKETSIZE	64
#define SLEEP_TIME 7 // spaci cas mezi jednotlivymi prujezdy handleru na lokalnim seznam portu v interface
// cekani mezi odesilanim paketu z jedne domeny
#define MIN_WAITING 100000
#define MAX_WAITING 500000
#define RAND_MAX 2147483647

// mutexy pro globalni frontu portu
extern pthread_mutex_t mutex_queue_size;
extern pthread_mutex_t mutex_queue_remove;
extern pthread_mutex_t mutex_queue_insert;
// globalni fronta portu
extern struct queue *global_queue_tcp;
extern struct port *global_list_tcp;
extern struct port *pu_arr;
// globalni seznam adres
extern struct single_address *addresses;
 // globalni sniffer na ping
extern pcap_t *sniff;
extern bool alarm_signal; // globalni alarm co signalizuje, jestli se ping vypnul pomoci casu
extern bool decoy_ping_succ; // uspech pingu na domenu