# Makefile for egalito

include ../env.mk

ANALYSIS_SOURCES    = $(wildcard analysis/*.cpp)
BREAK_SOURCES       = $(wildcard break/*.cpp)
CHUNK_SOURCES       = $(wildcard chunk/*.cpp)
CONDUCTOR_SOURCES   = $(wildcard conductor/*.cpp)
DISASM_SOURCES      = $(wildcard disasm/*.cpp)
ELF_SOURCES         = $(wildcard elf/*.cpp)
GENERATE_SOURCES    = $(wildcard generate/*.cpp)
INSTR_SOURCES       = $(wildcard instr/*.cpp)
LOAD_SOURCES        = $(wildcard load/*.cpp)
ifeq (aarch64,$(P_ARCH))
	LOAD_SOURCES += load/bootstrap-aarch64.S
else ifeq (x86_64,$(P_ARCH))
	LOAD_SOURCES += load/bootstrap-x86_64.s
endif
LOG_SOURCES         = $(wildcard log/*.cpp)
MAIN_SOURCES        = $(wildcard main/*.cpp)
OPERATION_SOURCES   = $(wildcard operation/*.cpp)
PASS_SOURCES        = $(wildcard pass/*.cpp)
TRANSFORM_SOURCES   = $(wildcard transform/*.cpp)
CMINUS_SOURCES      = $(wildcard cminus/*.c)

exe-filename = $(foreach s,$1,$(BUILDDIR)$(dir $s)$(basename $(notdir $s)))
obj-filename = $(foreach s,$1,$(BUILDDIR)$(dir $s)$(basename $(notdir $s)).o)
dep-filename = $(foreach s,$1,$(BUILDDIR)$(dir $s)$(basename $(notdir $s)).d)

TYPICAL_SOURCES = $(CHUNK_SOURCES) $(ELF_SOURCES) $(TRANSFORM_SOURCES) \
    $(LOG_SOURCES) $(PASS_SOURCES) $(DISASM_SOURCES) $(CONDUCTOR_SOURCES) \
    $(ANALYSIS_SOURCES) $(CMINUS_SOURCES) $(GENERATE_SOURCES) $(INSTR_SOURCES) \
    $(OPERATION_SOURCES) load/emulator.cpp
TYPICAL_OBJECTS = $(call obj-filename,$(TYPICAL_SOURCES))
TARGET_SOURCES = $(TYPICAL_SOURCES) $(MAIN_SOURCES)
TARGET_OBJECTS = $(call obj-filename,$(TARGET_SOURCES))
LOADER_SOURCES = $(TYPICAL_SOURCES) $(BREAK_SOURCES) $(LOAD_SOURCES)
LOADER_OBJECTS = $(call obj-filename,$(LOADER_SOURCES))
ALL_SOURCES = $(sort $(TARGET_SOURCES) $(LOADER_SOURCES))
ALL_OBJECTS = $(call obj-filename,$(ALL_SOURCES))

BUILDTREE = $(sort $(dir $(ALL_OBJECTS)))

TARGET = $(BUILDDIR)egalito
LOADER = $(BUILDDIR)loader
LIBRARY = $(BUILDDIR)libegalito.a
SHARED_LIBRARY = $(BUILDDIR)libegalito.so

OUTPUTS = $(TARGET) $(LOADER) $(LIBRARY) $(SHARED_LIBRARY)
SYMLINKS = $(notdir $(OUTPUTS))

GEN_TIMESTAMP = $(BUILDDIR).gen_timestamp

# Default target
.PHONY: all
all: $(GEN_TIMESTAMP) $(OUTPUTS) symlinks

$(BUILDDIR)load/emulator.o $(BUILDDIR)transform/data.o: | $(GEN_TIMESTAMP)
$(ALL_OBJECTS): | $(BUILDTREE)
$(BUILDTREE):
	@mkdir -p $@

symlinks: $(OUTPUTS) .symlinks
	@echo making symlinks...
	@ln -sf $(BUILDDIR)egalito
	@ln -sf $(BUILDDIR)loader
	@ln -sf $(BUILDDIR)libegalito.a
	@ln -sf $(BUILDDIR)libegalito.so
	@rm -f example
	@rm -f ex
	@ln -s ../test/example example
	@ln -s ../test/example/$(BUILDDIR) ex

.symlinks:
	@touch .symlinks

.PHONY: relink
relink: symlinks

$(GEN_TIMESTAMP): gencode | $(BUILDTREE)
	touch $@

gencode:
	$(MAKE) -C dep/rtld P_ARCH=$(P_ARCH)

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
$(BUILDDIR)%.so: %.c
	$(CC) -fPIC $(CFLAGS) $(DEPFLAGS) -DDEBUG_GROUP=$(shell echo $< | perl -ne 'm|^(\w+)/|g;print lc($$1)') -c -o $@ $<
$(BUILDDIR)%.so: %.cpp
	$(CXX) -fPIC $(CXXFLAGS) $(DEPFLAGS) -DDEBUG_GROUP=$(shell echo $< | perl -ne 'm|^(\w+)/|g;print lc($$1)') -c -o $@ $<

# Special files
$(BUILDDIR)load/usage.o: load/usage.cpp load/usage.h
	$(CXX) $(CXXFLAGS) $(DEPFLAGS) -DGIT_VERSION=$(shell git rev-parse --short HEAD) -c -o $@ $<
$(BUILDDIR)main/usage.o: main/usage.cpp main/usage.h
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
$(LIBRARY): $(TYPICAL_OBJECTS)
	$(AR) cr $(LIBRARY) $(TYPICAL_OBJECTS)
$(SHARED_LIBRARY): $(TYPICAL_OBJECTS:.o=.so)
	$(CXX) -shared -fPIC -Wl,-soname,libegalito.so $^ -o $@

# Other targets
.PHONY: clean
clean:
	-rm -rf $(BUILDDIR) .symlinks $(SYMLINKS) ex example symbols.elf
	-$(MAKE) -C dep/rtld clean
