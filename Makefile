# Makefile

CFLAGS=-O2 -g -std=c99 -lm -Wextra -Wall -pedantic

all: prime

# pokud je mas spustit a neexistuji, mel by je napred vytvorit. run: all

prime:
	gcc main.c functions.h functions.c ping.h ping.c -o scanner -lpthread -lpcap