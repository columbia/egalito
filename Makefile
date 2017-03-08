# root Makefile for egalito
# to change settings, see env.mk

.PHONY: all src test clean realclean
all: src test
src:
	$(MAKE) -C src
test: src
	$(MAKE) -C test
	$(MAKE) -C test/example

clean realclean:
	$(MAKE) -C src clean
	$(MAKE) -C test $@
	$(MAKE) -C test/example clean
