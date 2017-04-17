# Makefile to compute loader structures

include ../../../env.mk

READELF = $(CROSS)readelf
GDB = $(CROSS)gdb
TEST_PROG = $(BUILDDIR)load_test

CFLAGS = -std=c99 -Wall -Wextra -Wno-format -Wno-int-conversion -Wno-unused-parameter -g \
		-DRTLD_GLOBAL_SIZE=$(RTLD_GLOBAL_SIZE) \
		-DRTLD_GLOBAL_RO_SIZE=$(RTLD_GLOBAL_RO_SIZE)

LIBC = $(shell readlink -f $(shell $(CC) --print-file-name=libc.so.6))

RUN_GDB = $(GDB) -n -q -x reconstruct.py

GDB_GEN_FILES = rtld.h assign1.c assign2.c generate1.c generate2.c
GDB_GEN_FILES += pthread.h
TEST_GEN_FILES = rtld_data1.c rtld_data2.c
ALL_GEN_FILES = $(GDB_GEN_FILES) $(TEST_GEN_FILES)

ARCH_OUTPUT = $(TEST_PROG) $(BUILDDIR)test $(BUILDDIR)reproduce
ARCH_GDB_GEN_FILES = $(addprefix $(BUILDDIR),$(GDB_GEN_FILES))
ARCH_TEST_GEN_FILES = $(addprefix $(BUILDDIR),$(TEST_GEN_FILES))
ARCH_FILES = $(ARCH_OUTPUT) $(ARCH_GDB_GEN_FILES) $(ARCH_TEST_GEN_FILES)

.PHONY: all
all: test reproduce

test reproduce:

$(ARCH_FILES): | $(BUILDDIR)
$(BUILDDIR):
	@mkdir -p $@

depends: $(BUILDDIR)load_test
	$(eval INTERPRETER_NAME = $(shell $(READELF) -l $(TEST_PROG) | perl -ne '/\[Requesting program interpreter: (.*)\/(.*)\]/ && print "$$2\n"'))
	$(eval INTERPRETER = $(shell readlink -f $(shell $(CC) --print-file-name=$(INTERPRETER_NAME))))
	$(eval RTLD_GLOBAL_SIZE = $(shell $(READELF) --dyn-syms $(INTERPRETER) | grep rtld_global@ | awk '{ print $$3 }'))
	@echo $(RTLD_GLOBAL_SIZE)
	$(eval RTLD_GLOBAL_RO_SIZE = $(shell $(READELF) --dyn-syms $(INTERPRETER) | grep rtld_global_ro@ | awk '{ print $$3 }'))

$(BUILDDIR)rtld.h: depends
	$(RUN_GDB) -x rtld.gdb $(INTERPRETER) | grep -v 'done\.' \
		| sed 's/struct rtld/struct my_rtld/' > $@
$(BUILDDIR)%.c: %.gdb depends
	$(RUN_GDB) -x $< $(INTERPRETER) | grep -v 'done\.' > $@
ifneq ($(CROSS),)
 $(info "Not testing")
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

$(BUILDDIR)pthread.h: depends
	$(RUN_GDB) -x pthread.gdb $(LIBC) | grep -v 'done\.' \
		| sed 's/struct pthread/struct my_pthread/' > $@

sizes:
	@echo \# interpreter $(INTERPRETER)
	@echo \# rtld_global size $(RTLD_GLOBAL_SIZE)
	@echo \# rtld_global_ro size $(RTLD_GLOBAL_RO_SIZE)

$(BUILDDIR)load_test: $(BUILDDIR)load_test.o
	$(CC) $(CFLAGS) -o $@ $^
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
	@ln -sf $<

%.c: $(BUILDDIR)%.c relink
	@ln -sf $<

%: $(BUILDDIR)% relink
	@ln -sf $<

.PHONY: clean
clean:
	-rm -rf $(BUILDDIR) $(AUTO_GEN_FILES)
	-rm -f test reproduce $(GDB_GEN_FILES) $(TEST_GEN_FILES)
