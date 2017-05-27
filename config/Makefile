
include ../env.mk

PLATFORM_CONFIG_FILE = $(P_ARCH)-$(DISTRO).h

DIFF = $(if $(wildcard config.h),$(shell diff $(PLATFORM_CONFIG_FILE) config.h))

all: config.h

config.h:
	@if [ -e $(CONFIG_FILE) ]; then \
		cp $(PLATFORM_CONFIG_FILE) config.h; \
	else \
		echo "Please add a configuration file for $(P_ARCH) $(DISTRO)."; \
	fi

clean:
	@if [ "$(DIFF)" != "" ]; then \
		echo "config.h was modified. Please remove manually."; \
		diff $(PLATFORM_CONFIG_FILE) config.h; \
	else \
		rm -f config.h; \
	fi
