# Makefile

CFLAGS=-O2 -g -std=c99 -lm -Wextra -Wall -pedantic

all: prime

# pokud je mas spustit a neexistuji, mel by je napred vytvorit. run: all

prime: functions.h functions.c
	gcc main.c -o scanner