# Makefile for test cases

CC = gcc

CFLAGS	=

P_ARCH := $(shell uname -m)
ifeq (aarch64,$(P_ARCH))
	CFLAGS += -DARCH_AARCH64
else ifeq (x86_64,$(P_ARCH))
	CFLAGS += -DARCH_X86_64
else
$(error Unsupported platform, we only handle aarch64 and x86_64)
endif

TARGETS = hello hello-static helloq hi0 hi0-q

.PHONY: all
all: $(TARGETS)

hello: hello.c
	$(CC) $(CFLAGS) $^ -o $@
hello-static: hello.c
	$(CC) $(CFLAGS) $^ -o $@ -static
helloq: hello.c
	$(CC) $(CFLAGS) $^ -o $@ -Wl,-q
hi0: hi0.c hi0-s.S
	$(CC) $(CFLAGS) $^ -o $@
hi0-q: hi0.c hi0-s.S
	$(CC) $(CFLAGS) $^ -o $@ -Wl,-q

hi0-static: hi0.c hi0-s.S
	$(CC) $(CFLAGS) $^ -o $@ -static

.PHONY: clean
clean:
	-$(RM) $(TARGETS)
