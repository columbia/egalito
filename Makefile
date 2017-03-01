# root Makefile for egalito
# to change settings, see env.mk

.PHONY: all src test clean
all: src test
src:
	$(MAKE) -C src
test: src
	$(MAKE) -C test
	$(MAKE) -C test/example

clean:
	$(MAKE) -C src clean
	$(MAKE) -C test clean
	$(MAKE) -C test/example clean
