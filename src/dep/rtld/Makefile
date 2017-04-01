# Makefile to compute loader structures

P_ARCH ?= $(shell uname -m)
ifeq (aarch64,$(P_ARCH))
	BUILDDIR = build_aarch64/
else ifeq (x86_64,$(P_ARCH))
	BUILDDIR = build_x86_64/
else
	$(error Unsupported platform, we only handle aarch64 and x86_64)
endif

CC = gcc
CFLAGS = -std=c99 -Wall -Wextra -Wno-format -Wno-int-conversion -Wno-unused-parameter -g \
    -DRTLD_GLOBAL_SIZE=$(RTLD_GLOBAL_SIZE) \
    -DRTLD_GLOBAL_RO_SIZE=$(RTLD_GLOBAL_RO_SIZE)

INTERPRETER = $(shell readelf -l /bin/ls | perl -ne '/\[Requesting program interpreter: (.*)\]/ && print "$$1\n"')
LIBC = $(shell /usr/bin/ldd /bin/ls | grep libc.so | awk '{ print $$3 }')
RTLD_GLOBAL_SIZE = $(shell readelf --dyn-syms $(INTERPRETER) | grep rtld_global@ | awk '{ print $$3 }')
RTLD_GLOBAL_RO_SIZE = $(shell readelf --dyn-syms $(INTERPRETER) | grep rtld_global_ro@ | awk '{ print $$3 }')

RUN_GDB = gdb -n -q -x reconstruct.py

GDB_GEN_FILES = rtld.h assign1.c assign2.c generate1.c generate2.c
GDB_GEN_FILES += pthread.h
TEST_GEN_FILES = rtld_data1.c rtld_data2.c
ALL_GEN_FILES = $(GDB_GEN_FILES) $(TEST_GEN_FILES)

ARCH_OUTPUT = $(BUILDDIR)test $(BUILDDIR)reproduce
ARCH_GDB_GEN_FILES = $(addprefix $(BUILDDIR),$(GDB_GEN_FILES))
ARCH_TEST_GEN_FILES = $(addprefix $(BUILDDIR),$(TEST_GEN_FILES))
ARCH_FILES = $(ARCH_OUTPUT) $(ARCH_GDB_GEN_FILES) $(ARCH_TEST_GEN_FILES)

.PHONY: all
all: test reproduce

test reproduce:

$(ARCH_FILES): | $(BUILDDIR)
$(BUILDDIR):
	@mkdir -p $@

$(BUILDDIR)rtld.h:
	$(RUN_GDB) -x rtld.gdb $(INTERPRETER) | grep -v 'done\.' \
		| sed 's/struct rtld/struct my_rtld/' > $@
$(BUILDDIR)%.c: %.gdb
	$(RUN_GDB) -x $< $(INTERPRETER) | grep -v 'done\.' > $@
$(BUILDDIR)rtld_data1.c: test
	./test 1 > $@
$(BUILDDIR)rtld_data2.c: test
	./test 2 > $@
$(BUILDDIR)pthread.h:
	$(RUN_GDB) -x pthread.gdb $(LIBC) | grep -v 'done\.' \
		| sed 's/struct pthread/struct my_pthread/' > $@

sizes:
	@echo \# interpreter $(INTERPRETER)
	@echo \# rtld_global size $(RTLD_GLOBAL_SIZE)
	@echo \# rtld_global_ro size $(RTLD_GLOBAL_RO_SIZE)

$(BUILDDIR)test: $(BUILDDIR)test.o
	$(CC) $(CFLAGS) -o $@ $^ 
$(BUILDDIR)reproduce: $(BUILDDIR)reproduce.o
	$(CC) $(CFLAGS) -o $@ $^ 
$(BUILDDIR)test.o: test.c $(GDB_GEN_FILES)
$(BUILDDIR)reproduce.o: reproduce.c $(GDB_GEN_FILES) $(TEST_GEN_FILES)

$(BUILDDIR)%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

.PHONY: relink

%.h: $(BUILDDIR)%.h relink
	ln -sf $<

%.c: $(BUILDDIR)%.c relink
	ln -sf $<

%: $(BUILDDIR)% relink
	ln -sf $<

.PHONY: clean
clean:
	-rm -rf $(BUILDDIR) $(AUTO_GEN_FILES)
	-rm -f test reproduce $(GDB_GEN_FILES) $(TEST_GEN_FILES)

