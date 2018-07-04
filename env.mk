# Setup for egalito compilation environment

# Compute the root directory of the repo, containing env.mk.
EGALITO_ROOT_DIR := $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))

CC      = $(EGALITO_CCACHE) $(CROSS)gcc
CXX     = $(EGALITO_CCACHE) $(CROSS)g++

AS      = $(CC)
LINK    = $(CXX)

AR      = ar

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
ifneq ($(RTLD_CROSS),)
	RTLD_EXEC = $(RTLD_CROSS)
else
	$(error Specify command to execute rtld for currect arch)
endif
endif

CAPSTONE_DIR = $(EGALITO_ROOT_DIR)/dep/capstone/install
GENERIC_FLAGS += -I $(CAPSTONE_DIR)/include

OPT_FLAGS       = -g3 -O2
DEPFLAGS        = -MT '$@ $(@:.o=.so) $(@:.o=.d)' -MMD -MF $(@:.o=.d) -MP
CFLAGS          = -std=gnu99 $(GENERIC_FLAGS) $(OPT_FLAGS)
CXXFLAGS        = -std=c++14 $(GENERIC_FLAGS) $(OPT_FLAGS)
CLDFLAGS        = $(CROSSLD) -L $(CAPSTONE_DIR)/lib -lcapstone -lkeystone -Wl,-rpath,$(abspath $(CAPSTONE_DIR)/lib)

ifdef PROFILE  # set PROFILE=1 to enable gprof profiling
	CFLAGS += -no-pie -pg
	CXXFLAGS += -no-pie -pg
	CLDFLAGS += -no-pie -pg
endif

ifdef STACK_PROTECTOR  # set STACK_PROTECTOR=1 to enable -fstack-protector flag
	CFLAGS += -fstack-protector-all -D EGALITO_STACK_PROTECTOR
	CXXFLAGS += -fstack-protector-all -D EGALITO_STACK_PROTECTOR
else
	CFLAGS += -fno-stack-protector
	CXXFLAGS += -fno-stack-protector
endif

ifneq ($(CROSS),)
	P_ARCH := $(strip $(shell echo $(CC) | awk -F- '{print $$1}'))
else
	P_ARCH := $(shell uname -m)
	ifeq (armv7l,$(P_ARCH))
		P_ARCH = arm
	endif
	DISTRO = $(word 3,$(shell lsb_release -i))
endif
export P_ARCH

$(if $(VERBOSE),$(info "Building for $(P_ARCH)"))

ifeq (aarch64,$(P_ARCH))
	CFLAGS += -DARCH_AARCH64
	CXXFLAGS += -DARCH_AARCH64
	AFLAGS += -DARCH_AARCH64
	BUILDDIR = build_aarch64/
else ifeq (x86_64,$(P_ARCH))
	CFLAGS += -DARCH_X86_64
	CXXFLAGS += -DARCH_X86_64
	AFLAGS += -DARCH_X86_64
	BUILDDIR = build_x86_64/
else ifeq (arm,$(P_ARCH))
	CFLAGS += -DARCH_ARM
	CXXFLAGS += -DARCH_ARM
	AFLAGS += -DARCH_ARM
	BUILDDIR = build_arm/
else
	$(error "Unsupported platform, we only handle arm, aarch64, and x86_64")
endif

GLIBCDIR = $(dirname $(shell $(CC) --print-file-name=libc.so))
CRTI = $(shell $(CC) --print-file-name=crti.o)
CRTBEGIN = $(shell $(CC) --print-file-name=crtbegin.o)
CRTEND = $(shell $(CC) --print-file-name=crtend.o)
CRTN = $(shell $(CC) --print-file-name=crtn.o)

# We do not include crt1.o in STARTFILES because we specify our own _start.
STARTFILES = $(CRTI) $(CRTBEGIN)
ENDFILES = $(CRTEND) $(CRTN)

ifeq ($(VERBOSE),)
	SHORT_AS    = @echo "AS   $<"; $(AS)
	SHORT_CC    = @echo "CC   $<"; $(CC)
	SHORT_CXX   = @echo "CXX  $<"; $(CXX)
	SHORT_LINK  = @echo "LINK $@"; $(LINK)
	SHORT_AR    = @echo "AR   $@"; $(AR)
else
	SHORT_AS    = $(AS)
	SHORT_CC    = $(CC)
	SHORT_CXX   = $(CXX)
	SHORT_LINK  = $(LINK)
	SHORT_AR    = $(AR)
endif
ifneq ($(MAKEVERBOSE),)
    MAKE += --no-print-directory
    short-make = @+echo '>>>' MAKE -C ${1} ${2} ;\
        $(MAKE) -C ${1} ${2} && echo '<<<' MAKE -C ${1} ${2}
else
    short-make = +$(MAKE) -C ${1} ${2}
endif

# Rules
$(BUILDDIR)%.o: %.s
	$(SHORT_AS) -fPIC -c $< -o $@
$(BUILDDIR)%.o: %.S
	$(SHORT_AS) -fPIC $(AFLAGS) $(DEPFLAGS) -c $< -o $@
$(BUILDDIR)%.o: %.c
	$(SHORT_CC) $(CFLAGS) $(DEPFLAGS) -DDEBUG_GROUP=$(shell echo $< | perl -ne 'm|^(\w+)/|g;print lc($$1)') -c -o $@ $<
$(BUILDDIR)%.o: %.cpp
	$(SHORT_CXX) $(CXXFLAGS) $(DEPFLAGS) -DDEBUG_GROUP=$(shell echo $< | perl -ne 'm|^(\w+)/|g;print lc($$1)') -c -o $@ $<
$(BUILDDIR)%.so: %.s
	$(SHORT_AS) -fPIC -c $< -o $@
$(BUILDDIR)%.so: %.S
	$(SHORT_AS) -fPIC $(AFLAGS) $(DEPFLAGS) -c -o $@ $<
$(BUILDDIR)%.so: %.c
	$(SHORT_CC) -fPIC $(CFLAGS) -DDEBUG_GROUP=$(shell echo $< | perl -ne 'm|^(\w+)/|g;print lc($$1)') -c -o $@ $<
$(BUILDDIR)%.so: %.cpp
	$(SHORT_CXX) -fPIC $(CXXFLAGS) -DDEBUG_GROUP=$(shell echo $< | perl -ne 'm|^(\w+)/|g;print lc($$1)') -c -o $@ $<
