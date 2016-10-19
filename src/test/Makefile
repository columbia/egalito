# Makefile for test cases

CC = gcc

TARGETS = hello hello-static helloq hi0 hi0-q

.PHONY: all
all: $(TARGETS)

hello: hello.c
	$(CC) $^ -o $@
hello-static: hello.c
	$(CC) $^ -o $@
helloq: hello.c
	$(CC) $^ -o $@ -Wl,-q
hi0: hi0.c hi0-s.s
	$(CC) $^ -o $@
hi0-q: hi0.c hi0-s.s
	$(CC) $^ -o $@ -Wl,-q

hi0-static: hi0.c hi0-s.s
	$(CC) $^ -o $@ -static

.PHONY: clean
clean:
	-$(RM) $(TARGETS)
