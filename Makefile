# root Makefile for egalito
# to change settings, see env.mk

ifdef USE_CONFIG
	include $(USE_CONFIG)
	export
endif

ifeq ($(MAKEVERBOSE),)
    MAKE += --no-print-directory
    short-make = @+echo '>>>' MAKE -C ${1} ${2} ;\
        $(MAKE) -C ${1} ${2} ; echo '<<<' MAKE -C ${1} ${2}
else
    short-make = +$(MAKE) -C ${1} ${2}
endif

.PHONY: all config src test app clean realclean
all: src test app
	@true
src: | config
	$(call short-make,src)
test: src
	$(call short-make,test)
	$(call short-make,test/example)
	$(call short-make,test/binary all symlinks)
app: src | test
	$(call short-make,app)

config:
	$(call short-make,config)

clean realclean:
	$(call short-make,app,clean)
	$(call short-make,src,clean)
	$(call short-make,test,$@)
	$(call short-make,test/example,clean)
	$(call short-make,test/binary,clean)
	$(call short-make,config,clean)
