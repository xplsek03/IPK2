all: prime

prime:
	gcc -g ipk-scan.c functions.h functions.c ping.h ping.c -o ipk-scan -lpthread -lpcap
