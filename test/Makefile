# Makefile for egalito test code

include ../env.mk

DIRS = framework unit scripts codegen
.PHONY: all $(DIRS)
all: unit

unit: framework

$(DIRS):
	$(MAKE) -C $@
