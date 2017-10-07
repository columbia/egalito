# Makefile to compute loader structures

include ../../../env.mk

READELF = $(CROSS)readelf
GDB = $(CROSS)gdb

CFLAGS = -std=c99 -Wall -Wextra -Wno-format -Wno-int-conversion -Wno-unused-parameter -g
CFLAGS_D =	-DRTLD_GLOBAL_SIZE=$(shell cat $(BUILDDIR)rtld_global_size) \
		-DRTLD_GLOBAL_RO_SIZE=$(shell cat $(BUILDDIR)rtld_global_ro_size)

LIBC = $(shell readlink -f $(shell $(CC) --print-file-name=libc.so.6))

RUN_GDB = $(GDB) -n -q -x reconstruct.py

GDB_GEN_FILES = rtld.h assign1.c assign2.c generate1.c generate2.c
GDB_GEN_FILES += pthread.h
GDB_GEN_FILES += tcbhead.h
TEST_GEN_FILES = rtld_data1.c rtld_data2.c
ALL_GEN_FILES = $(GDB_GEN_FILES) $(TEST_GEN_FILES)

ARCH_OUTPUT = $(BUILDDIR)load_test $(BUILDDIR)test $(BUILDDIR)reproduce
ARCH_GDB_GEN_FILES = $(addprefix $(BUILDDIR),$(GDB_GEN_FILES))
ARCH_TEST_GEN_FILES = $(addprefix $(BUILDDIR),$(TEST_GEN_FILES))
ARCH_FILES = $(ARCH_OUTPUT) $(ARCH_GDB_GEN_FILES) $(ARCH_TEST_GEN_FILES)

.PHONY: all
all: test reproduce
	@true

test reproduce:

$(ARCH_FILES): | $(BUILDDIR)
$(BUILDDIR):
	@mkdir -p $@

.PHONY: depends
# Generate files whose contents will be passed as arguments to GCC.
depends: $(BUILDDIR)interpreter $(BUILDDIR)rtld_global_size $(BUILDDIR)rtld_global_ro_size | $(BUILDDIR)

$(BUILDDIR)interpreter: $(BUILDDIR)load_test
	$(eval INTERPRETER_NAME = $(shell $(READELF) -l $(BUILDDIR)load_test | perl -ne '/\[Requesting program interpreter: (.*)\/(.*)\]/ && print "$$2\n"'))
	readlink -f $(shell $(CC) --print-file-name=$(INTERPRETER_NAME)) > $@
$(BUILDDIR)rtld_global_size: $(BUILDDIR)interpreter
	$(READELF) --dyn-syms $(shell cat $(BUILDDIR)interpreter) | grep rtld_global@ | awk '{ print $$3 }' > $@
$(BUILDDIR)rtld_global_ro_size: $(BUILDDIR)interpreter
	$(READELF) --dyn-syms $(shell cat $(BUILDDIR)interpreter) | grep rtld_global_ro@ | awk '{ print $$3 }' > $@

$(BUILDDIR)rtld.h: | depends
	$(RUN_GDB) -x rtld.gdb $(shell cat $(BUILDDIR)interpreter) | grep -v 'done\.' \
		| sed 's/struct rtld/struct my_rtld/' > $@
$(BUILDDIR)pthread.h: | depends
	$(RUN_GDB) -x pthread.gdb $(LIBC) | grep -v 'done\.' \
		| sed 's/struct pthread/struct my_pthread/' > $@
$(BUILDDIR)tcbhead.h: | depends
	$(RUN_GDB) -x tcbhead.gdb $(shell cat $(BUILDDIR)interpreter) | grep -v 'done\.' \
		| sed 's/tcbhead_t/struct my_tcbhead_t/' \
		| sed 's/private/my_private/' > $@

$(BUILDDIR)%.c: %.gdb | depends
	$(RUN_GDB) -x $< $(shell cat $(BUILDDIR)interpreter) | grep -v 'done\.' > $@
ifneq ($(CROSS),)
$(BUILDDIR)rtld_data1.c: test
	$(RTLD_EXEC) ./test 1 > $@
$(BUILDDIR)rtld_data2.c: test
	$(RTLD_EXEC) ./test 2 > $@
else
$(BUILDDIR)rtld_data1.c: test
	./test 1 > $@
$(BUILDDIR)rtld_data2.c: test
	./test 2 > $@
endif

# load_test is used only to determine the system dynamic loader (ld.so)
$(BUILDDIR)load_test: load_test.c
	$(CC) $(CFLAGS) -o $@ $^
$(BUILDDIR)test: $(BUILDDIR)test.o
	$(CC) $(CFLAGS) -o $@ $^
$(BUILDDIR)reproduce: $(BUILDDIR)reproduce.o
	$(CC) $(CFLAGS) -o $@ $^
$(BUILDDIR)test.o: test.c $(GDB_GEN_FILES)
	$(CC) $(CFLAGS) $(CFLAGS_D) -c -o $@ $<
$(BUILDDIR)reproduce.o: reproduce.c $(GDB_GEN_FILES) $(TEST_GEN_FILES)
	$(CC) $(CFLAGS) $(CFLAGS_D) -c -o $@ $<
$(BUILDDIR)%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

.PHONY: relink

%.h: $(BUILDDIR)%.h relink
	@ln -sf $<

%.c: $(BUILDDIR)%.c relink
	@ln -sf $<

%: $(BUILDDIR)% relink
	@ln -sf $<

.PHONY: clean
clean:
	-rm -rf $(BUILDDIR) $(AUTO_GEN_FILES)
	-rm -f test reproduce $(GDB_GEN_FILES) $(TEST_GEN_FILES)
