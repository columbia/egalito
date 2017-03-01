# Setup for egalito compilation environment

CC  = gcc
CXX = g++
GENERIC_FLAGS   = -Wall -Wextra -Wno-unused-parameter -I.
OPT_FLAGS       = -g -O2
DEPFLAGS        = -MT '$@ $(@:.o=.d)' -MMD -MP
CFLAGS          = -std=gnu99 $(GENERIC_FLAGS) $(OPT_FLAGS)
CXXFLAGS        = -std=c++11 $(GENERIC_FLAGS) $(OPT_FLAGS)
CLDFLAGS        = -lcapstone -Wl,-q
#LDFLAGS         = -lcapstone -q
#LDFLAGS2        = `gcc --print-file-name=libstdc++.a` `gcc --print-file-name=libgcc.a`
#LDFLAGS2        = $(shell g++ -print-search-dirs 2>&1 | grep libraries | sed 's/libraries: =/:/; s/:/ -L/g') -lstdc++ --start-group -lgcc -lgcc_eh -lc --end-group

ifdef PROFILE  # set PROFILE=1 to enable gprof profiling
    CFLAGS += -no-pie -pg
    CXXFLAGS += -no-pie -pg
    CLDFLAGS += -no-pie -pg
endif

P_ARCH := $(shell uname -m)
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

ifneq (,$(wildcard /usr/lib/x86_64-linux-gnu))
	GLIBCDIR = /usr/lib/x86_64-linux-gnu
else ifneq (,$(wildcard /usr/lib/aarch64-linux-gnu))
	GLIBCDIR = /usr/lib/aarch64-linux-gnu
else ifneq (,$(wildcard /usr/lib64))
	GLIBCDIR = /usr/lib64
endif
#STARTFILES = $(GLIBCDIR)/crt1.o $(GLIBCDIR)/crti.o `gcc --print-file-name=crtbeginT.o`
STARTFILES = $(GLIBCDIR)/crti.o `gcc --print-file-name=crtbegin.o`
ENDFILES = `gcc --print-file-name=crtend.o` $(GLIBCDIR)/crtn.o
