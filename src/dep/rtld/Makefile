# Makefile to compute loader structures

CC = gcc
CFLAGS = -std=c99 -Wall -Wextra -Wno-format -Wno-int-conversion -Wno-unused-parameter -g \
    -DRTLD_GLOBAL_SIZE=$(RTLD_GLOBAL_SIZE) \
    -DRTLD_GLOBAL_RO_SIZE=$(RTLD_GLOBAL_RO_SIZE)

INTERPRETER = $(shell readelf -l /bin/ls | perl -ne '/\[Requesting program interpreter: (.*)\]/ && print "$$1\n"')
RTLD_GLOBAL_SIZE = $(shell readelf --dyn-syms $(INTERPRETER) | grep rtld_global@ | awk '{ print $$3 }')
RTLD_GLOBAL_RO_SIZE = $(shell readelf --dyn-syms $(INTERPRETER) | grep rtld_global_ro@ | awk '{ print $$3 }')

RUN_GDB = gdb -q -x reconstruct.py

AUTO_GEN_FILES = rtld.h assign1.c assign2.c generate1.c generate2.c rtld_data1.c rtld_data2.c

.PHONY: all
all: $(AUTO_GEN_FILES) test reproduce

rtld.h:
	$(RUN_GDB) -x rtld.gdb $(INTERPRETER) | grep -v 'done\.' \
		| sed 's/struct rtld/struct my_rtld/' > rtld.h
%.c: %.gdb
	$(RUN_GDB) -x $< $(INTERPRETER) | grep -v 'done\.' > $@
rtld_data1.c: test
	./test 1 > rtld_data1.c
rtld_data2.c: test
	./test 2 > rtld_data2.c

sizes:
	@echo \# interpreter $(INTERPRETER)
	@echo \# rtld_global size $(RTLD_GLOBAL_SIZE)
	@echo \# rtld_global_ro size $(RTLD_GLOBAL_RO_SIZE)

test: test.o
	$(CC) $(CFLAGS) -o $@ $^ 
reproduce: reproduce.o
	$(CC) $(CFLAGS) -o $@ $^ 

.PHONY: clean
clean:
	-rm $(AUTO_GEN_FILES) test test.o reproduce reproduce.o
