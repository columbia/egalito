# root Makefile for egalito
# to change settings, see env.mk

.PHONY: all src test app clean realclean
all: src test app
src:
	$(MAKE) -C src
test: src
	$(MAKE) -C test
	$(MAKE) -C test/example
app: src
	$(MAKE) -C app

clean realclean:
	$(MAKE) -C src clean
	$(MAKE) -C test $@
	$(MAKE) -C test/example clean
