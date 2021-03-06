#define PCKT_LEN 512
#define PACKETSIZE	64

// spaci cas mezi jednotlivymi prujezdy handleru na lokalnim seznam portu v interface
#define SLEEP_TIME 5

// cekani mezi odesilanim tcp paketu z jedne domeny
#define MIN_WAITING 50000
#define MAX_WAITING 250000
#define RAND_MAX 2147483647

// nenulova hodnota. Pokud 1: pouzije se ip rozhrani. pocet decoy ip adres jednoho rozhrani
#define DECOYS 2

// rozsah zdrojovych portu
#define PORT_RANGE_START 50000
#define PORT_RANGE_END 60000

#define MACSPOOF 1 // defualtne zapnuta zmena mac adresy po kazdem odeslani syn paketu na pouzitem rozhrani

#define UDPMINWAIT 600000 // min cekaci doba na obdrzeni odpovedi na udp paket
#define UDPMAXWAIT 1200000 // max cekaci odba odpoved na udp paket

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