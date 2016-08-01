# Makefile for test cases

CC = gcc

TARGETS = hello hello-static hi0

.PHONY: all
all: $(TARGETS)

hello: hello.c
	$(CC) $^ -o $@
hello-static: hello.c
	$(CC) $^ -o $@
hi0: hi0.c hi0-s.s
	$(CC) $^ -o $@

.PHONY: clean
clean:
	-$(RM) $(TARGETS)
