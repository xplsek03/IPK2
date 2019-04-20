#include "settings.h"

pthread_mutex_t mutex_queue_remove = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t mutex_queue_size = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t mutex_queue_insert = PTHREAD_MUTEX_INITIALIZER;

// globalni fronta portu
struct queue *global_queue_tcp = null;
struct port *global_list_tcp = null;
struct port *pu_arr = null;
// globalni seznam adres
struct single_address *addresses = null;
 // globalni sniffer na ping
pcap_t *sniff = null;
bool alarm_signal = false; // globalni alarm co signalizuje, jestli se ping vypnul pomoci casu
bool decoy_ping_succ = false; // uspech pingu na domenu
