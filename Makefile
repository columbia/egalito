# root Makefile for egalito
# to change settings, see env.mk

ifdef USE_CONFIG
	include $(USE_CONFIG)
	export
endif

.PHONY: all config src test app clean realclean
all: src test app
src: | config
	$(MAKE) -C src
test: src
	$(MAKE) -C test
	$(MAKE) -C test/example
	$(MAKE) -C test/binary all symlinks
app: src | test
	$(MAKE) -C app


config:
	$(MAKE) -C config

clean realclean:
	$(MAKE) -C app clean
	$(MAKE) -C src clean
	$(MAKE) -C test $@
	$(MAKE) -C test/example clean
	$(MAKE) -C test/binary clean
	$(MAKE) -C config clean
