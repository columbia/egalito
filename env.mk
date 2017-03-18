# Setup for egalito compilation environment

CC  = $(CROSS)gcc
CXX = $(CROSS)g++

GENERIC_FLAGS   = -Wall -Wextra -Wno-unused-parameter -I.

ifneq ($(CROSS),)
ifneq ($(CAPSTONE_INC),)
	GENERIC_FLAGS += -isystem $(CAPSTONE_INC)
else
	$(error Capstone Include directory not defined)
endif
ifneq ($(CAPSTONE_LIB),)
	CROSSLD = -L $(CAPSTONE_LIB)
else
	$(error Capstone Lib directory not defined)
endif
endif

OPT_FLAGS       = -g -O2
DEPFLAGS        = -MT '$@ $(@:.o=.d)' -MMD -MP
CFLAGS          = -std=gnu99 $(GENERIC_FLAGS) $(OPT_FLAGS)
CXXFLAGS        = -std=c++11 $(GENERIC_FLAGS) $(OPT_FLAGS)
CLDFLAGS        = $(CROSSLD) -lcapstone -Wl,-q

ifdef PROFILE  # set PROFILE=1 to enable gprof profiling
	CFLAGS += -no-pie -pg
	CXXFLAGS += -no-pie -pg
	CLDFLAGS += -no-pie -pg
endif

ifneq ($(CROSS),)
	P_ARCH=$(strip $(shell echo $(CC) | awk -F- '{print $$1}'))
else
	P_ARCH=$(shell uname -m)
endif

$(info "Building for $(P_ARCH)")

ifeq (aarch64,$(P_ARCH))
	CFLAGS += -DARCH_AARCH64
	CXXFLAGS += -DARCH_AARCH64
	BUILDDIR = build_aarch64/
else ifeq (x86_64,$(P_ARCH))
	CFLAGS += -DARCH_X86_64
	CXXFLAGS += -DARCH_X86_64
	BUILDDIR = build_x86_64/
else
$(error Unsupported platform, we only handle aarch64 and x86_64)
endif

CFLAGS += '-DTESTDIR="example/$(BUILDDIR)"'
CXXFLAGS += '-DTESTDIR="example/$(BUILDDIR)"'

GLIBCDIR = $(dirname $(shell $(CC) --print-file-name=libc.so))
CRTI = $(shell $(CC) --print-file-name=crti.o)
CRTBEGIN = $(shell $(CC) --print-file-name=crtbegin.o)
CRTEND = $(shell $(CC) --print-file-name=crtend.o)
CRTN = $(shell $(CC) --print-file-name=crtn.o)

STARTFILES = $(CRTI) $(CRTBEGIN)
ENDFILES = $(CRTEND) $(CRTN)
