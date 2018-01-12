include ../../env.mk

GDB = $(CROSS)gdb
RUN_GDB = $(GDB) -n -batch-silent -x determine.py

.PHONY: all
all: ifunc.h

ifunc.h: determine

determine: determine.c
	@$(CC) -O0 -fno-builtin -o $@ $^
	@$(RUN_GDB) -x determine.gdb $@

clean realclean:
	-@rm determine ifunc.h
