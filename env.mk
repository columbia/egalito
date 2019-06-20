# Setup for egalito compilation environment

# Compute the root directory of the repo, containing env.mk.
EGALITO_ROOT_DIR := $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))

# Optional settings:
#   USE_KEYSTONE=1
#   USE_LOADER=1
#   USE_WIN64_PE=1
#   VERBOSE=1
#   PROFILE=1
#   STACK_PROTECTOR=1

# To cross-compile, set e.g. CROSS=aarch64-linux-gnu-
#   for loader support, also set RTLD_TARGET to an appropriate simulator for
#   running binaries (e.g. qemu-user-*).
# To cross-analyze, set CROSS as before and
# 	also CROSS_ANALYZE=1 (the loader is not supported in this config)
ifneq ($(CROSS),)
ifeq ($(CROSS_ANALYZE),1)
	USE_LOADER=0
endif
endif

ifeq ($(USE_LOADER),)
	USE_LOADER=1
endif

ifeq ($(USE_LOADER),1)
ifneq ($(CROSS),)
ifneq ($(RTLD_TARGET),)
	RTLD_EXEC = $(RTLD_TARGET)
else
$(error Specify command to execute target rtld for current arch)
endif
endif
endif

ifneq ($(CROSS_ANALYZE),1)
CC         = $(EGALITO_CCACHE) $(CROSS)gcc
CXX        = $(EGALITO_CCACHE) $(CROSS)g++
else
CC         = $(EGALITO_CCACHE) gcc
CXX        = $(EGALITO_CCACHE) g++
endif
TARGET_CC  = $(EGALITO_CCACHE) $(CROSS)gcc
TARGET_CXX = $(EGALITO_CCACHE) $(CROSS)g++

AS         = $(CC)
LINK       = $(CXX)

AR         = ar

GENERIC_FLAGS   = -Wall -Wextra -Wno-unused-parameter -I.

ifneq ($(CROSS),)
ifneq ($(CAPSTONE_INC),)
	GENERIC_FLAGS += -isystem $(CAPSTONE_INC)
endif
ifneq ($(CAPSTONE_LIB),)
	CROSSLD = -L $(CAPSTONE_LIB)
endif
endif

CAPSTONE_DIR = $(EGALITO_ROOT_DIR)/dep/capstone/install
GENERIC_FLAGS += -I $(CAPSTONE_DIR)/include
ifeq ($(USE_KEYSTONE),1)
KEYSTONE_DIR = $(EGALITO_ROOT_DIR)/dep/keystone
GENERIC_FLAGS += -I $(KEYSTONE_DIR)/include
endif
ifeq ($(USE_WIN64_PE),1)
WIN64_PE_DIR = $(EGALITO_ROOT_DIR)/dep/pe-parse
GENERIC_FLAGS += -I $(WIN64_PE_DIR)/pe-parser-library/include
endif
ifeq ($(USE_LOADER),1)
GENERIC_FLAGS += -DUSE_LOADER
endif

OPT_FLAGS       = -g3 -Og
DEPFLAGS        = -MT '$@ $(@:.o=.so) $(@:.o=.d)' -MMD -MF $(@:.o=.d) -MP
CFLAGS          = -std=gnu99 $(GENERIC_FLAGS) $(OPT_FLAGS)
CXXFLAGS        = -std=c++14 $(GENERIC_FLAGS) $(OPT_FLAGS)
CLDFLAGS        = $(CROSSLD)

CLDFLAGS		+= -L $(CAPSTONE_DIR)/lib -lcapstone \
	-Wl,-rpath,$(abspath $(CAPSTONE_DIR)/lib)

ifdef USE_KEYSTONE  # set USE_KEYSTONE=1 to link with str->instr assembler
	CLDFLAGS        += -L $(KEYSTONE_DIR)/build/llvm/lib -lkeystone \
	    -Wl,-rpath,$(abspath $(KEYSTONE_DIR)/build/llvm/lib)
	CFLAGS += -D USE_KEYSTONE
	CXXFLAGS += -D USE_KEYSTONE
endif

ifdef USE_WIN64_PE  # set USE_WIN64_PE=1 to link with str->instr assembler
	CLDFLAGS        += -L $(WIN64_PE_DIR)/build/pe-parser-library -lpe-parser-library
	CFLAGS += -D USE_WIN64_PE
	CXXFLAGS += -D USE_WIN64_PE
endif

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

ifneq ($(CROSS_ANALYZE),)
	P_ARCH := $(strip $(shell echo $(CROSS) | awk -F- '{print $$1}'))
else
	P_ARCH := $(shell uname -m)
	ifeq (armv7l,$(P_ARCH))
		P_ARCH = arm
	endif
	DISTRO = $(word 3,$(shell lsb_release -i))
endif
export P_ARCH

$(if $(VERBOSE),$(info Building for $(P_ARCH)))

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
else ifeq (riscv64,$(P_ARCH))
	CFLAGS += -DARCH_RISCV
	CXXFLAGS += -DARCH_RISCV
	AFLAGS += -DARCH_RISCV
	BUILDDIR = build_riscv/
else
	$(error "Unsupported platform $(P_ARCH), we only handle arm, aarch64, riscv, and x86_64")
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
