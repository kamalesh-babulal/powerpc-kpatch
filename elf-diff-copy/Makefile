CC=gcc
CFLAGS=-g -Wall

.PHONY: all clean
all: elf-diff-copy


elf-diff-copy: elf-diff-copy.c
	$(CC) $(CFLAGS) -o $@ $^ -lelf

clean:
	rm -rf elf-diff-copy
