# Makefile for egalito

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
CFLAGS += '-DTESTDIR="test/$(BUILDDIR)"'
CXXFLAGS += '-DTESTDIR="test/$(BUILDDIR)"'

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

ANALYSIS_SOURCES    = $(wildcard analysis/*.cpp)
BREAK_SOURCES       = $(wildcard break/*.cpp)
CHUNK_SOURCES       = $(wildcard chunk/*.cpp)
CONDUCTOR_SOURCES   = $(wildcard conductor/*.cpp)
DISASM_SOURCES      = $(wildcard disasm/*.cpp)
ELF_SOURCES         = $(wildcard elf/*.cpp)
INTEGRATION_SOURCES = $(wildcard integration/*.cpp)
LOAD_SOURCES        = $(wildcard load/*.cpp)
ifeq (aarch64,$(P_ARCH))
	LOAD_SOURCES += load/bootstrap-aarch64.S
else ifeq (x86_64,$(P_ARCH))
	LOAD_SOURCES += load/bootstrap.s
endif
LOG_SOURCES         = $(wildcard log/*.cpp)
MAIN_SOURCES        = $(wildcard main/*.cpp)
PASS_SOURCES        = $(wildcard pass/*.cpp)
TRANSFORM_SOURCES   = $(wildcard transform/*.cpp)

exe-filename = $(foreach s,$1,$(BUILDDIR)$(dir $s)$(basename $(notdir $s)))
obj-filename = $(foreach s,$1,$(BUILDDIR)$(dir $s)$(basename $(notdir $s)).o)
dep-filename = $(foreach s,$1,$(BUILDDIR)$(dir $s)$(basename $(notdir $s)).d)

SOURCES = $(CHUNK_SOURCES) $(ELF_SOURCES) $(TRANSFORM_SOURCES) $(LOG_SOURCES) \
    $(PASS_SOURCES) $(DISASM_SOURCES) $(CONDUCTOR_SOURCES) $(ANALYSIS_SOURCES)
TYPICAL_OBJECTS = $(call obj-filename,$(SOURCES))
TARGET_SOURCES = $(SOURCES) $(MAIN_SOURCES)
TARGET_OBJECTS = $(call obj-filename,$(TARGET_SOURCES))
LOADER_SOURCES = $(SOURCES) $(BREAK_SOURCES) $(LOAD_SOURCES)
LOADER_OBJECTS = $(call obj-filename,$(LOADER_SOURCES))
ITEST_SOURCES = $(SOURCES) $(INTEGRATION_SOURCES)
ITEST_OBJECTS = $(call obj-filename,$(ITEST_SOURCES))
ALL_SOURCES = $(sort $(TARGET_SOURCES) $(LOADER_SOURCES) $(ITEST_SOURCES))
ALL_OBJECTS = $(call obj-filename,$(ALL_SOURCES))

BUILDTREE = $(sort $(dir $(ALL_OBJECTS)))

TARGET = $(BUILDDIR)egalito
LOADER = $(BUILDDIR)loader
ITEST = $(BUILDDIR)itest

# Default target
.PHONY: all
all: $(TARGET) $(LOADER) $(ITEST)

$(ALL_OBJECTS): | $(BUILDTREE)
$(BUILDTREE):
	mkdir -p $@

# Dependencies
DEPEND_FILES = $(call dep-filename,$(ALL_SOURCES))
-include $(DEPEND_FILES)

# Rules
$(BUILDDIR)%.o: %.s
	$(CC) -fPIC -c $< -o $@
$(BUILDDIR)%.o: %.S
	$(CC) -fPIC $(DEPFLAGS) -c $< -o $@
$(BUILDDIR)%.o: %.c
	$(CC) $(CFLAGS) $(DEPFLAGS) -DDEBUG_GROUP=$(shell echo $< | perl -ne 'm|^(\w+)/|g;print lc($$1)') -c -o $@ $<
$(BUILDDIR)%.o: %.cpp
	$(CXX) $(CXXFLAGS) $(DEPFLAGS) -DDEBUG_GROUP=$(shell echo $< | perl -ne 'm|^(\w+)/|g;print lc($$1)') -c -o $@ $<

# Special files
$(BUILDDIR)load/usage.o: load/usage.cpp
	$(CXX) $(CXXFLAGS) $(DEPFLAGS) -DGIT_VERSION=$(shell git rev-parse --short HEAD) -c -o $@ $<
$(BUILDDIR)elf/sharedlib.o: elf/sharedlib.cpp
	$(CXX) $(CXXFLAGS) $(DEPFLAGS) '-DLIBC_PATH="$(shell /usr/bin/ldd /bin/ls | grep libc.so | awk '{ print $$3 }')"' -c -o $@ $<

# Programs and libraries
$(TARGET): $(TARGET_OBJECTS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(CLDFLAGS)
$(LOADER): $(LOADER_OBJECTS)
	$(CXX) -static -o $@ -pg \
        -nostartfiles $(STARTFILES) $^ $(CLDFLAGS) $(ENDFILES) -Wl,--eh-frame-hdr \
        -Wl,-Ttext-segment=0x7400000 -Wl,-Trodata-segment=0x7600000
$(ITEST): $(ITEST_OBJECTS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(CLDFLAGS)

# Tests
REGRESSION_SOURCES = $(wildcard regression/*.cpp)
REGRESSION_OBJECTS = $(call obj-filename,$(REGRESSION_SOURCES))
REGRESSION_TESTS = $(call exe-filename,$(filter-out regression/elfgenmanager,$(REGRESSION_SOURCES:.cpp=)))
.PHONY: rtest
rtest: $(REGRESSION_TESTS)

$(REGRESSION_TESTS): % : %.o $(TYPICAL_OBJECTS) $(BUILDDIR)regression/elfgenmanager.o
	$(CXX) $(CXXFLAGS) -o $@ $^ $(CLDFLAGS)

$(REGRESSION_OBJECTS): | $(BUILDDIR)/regression
$(BUILDDIR)/regression:
	mkdir -p $@

# Other targets
.PHONY: clean
clean:
	-rm -rf $(BUILDDIR)
