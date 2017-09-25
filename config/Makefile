
include ../env.mk

PLATFORM_CONFIG_FILE = $(P_ARCH)-$(DISTRO).h

DIFF = $(if $(wildcard config.h),$(shell diff $(PLATFORM_CONFIG_FILE) config.h))

all: config.h

config.h: $(PLATFORM_CONFIG_FILE)
	@if [ -e $(PLATFORM_CONFIG_FILE) ]; then \
		if [ ! -e config.h ]; then \
			cp $(PLATFORM_CONFIG_FILE) config.h; \
		else \
			if [ "$(DIFF)" != "" ]; then \
				echo "default config is updated: please remove config.h to apply."; \
				diff $(PLATFORM_CONFIG_FILE) config.h; \
			fi \
		fi \
	fi

$(PLATFORM_CONFIG_FILE):
	@echo "Please add a new configuration file ($(PLATFORM_CONFIG_FILE))."

clean:
	@if [ "$(DIFF)" != "" ]; then \
		echo "config.h was modified: please remove manually."; \
		diff $(PLATFORM_CONFIG_FILE) config.h; \
	else \
		rm -f config.h; \
	fi

force-update:
	cp -a $(PLATFORM_CONFIG_FILE) config.h
