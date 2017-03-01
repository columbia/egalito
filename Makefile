# root Makefile for egalito
# to change settings, see env.mk

.PHONY: all src test
all: src test
src:
	$(MAKE) -C src
test:
	$(MAKE) -C test
