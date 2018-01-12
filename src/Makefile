# Makefile for egalito

include ../env.mk

ANALYSIS_SOURCES    = $(wildcard analysis/*.cpp)
ARCHIVE_SOURCES     = $(wildcard archive/*.cpp)
BREAK_SOURCES       = $(wildcard break/*.cpp)
CHUNK_SOURCES       = $(wildcard chunk/*.cpp)
CONDUCTOR_SOURCES   = $(wildcard conductor/*.cpp)
DISASM_SOURCES      = $(wildcard disasm/*.cpp)
DWARF_SOURCES       = $(wildcard dwarf/*.cpp)
ELF_SOURCES         = $(wildcard elf/*.cpp)
GENERATE_SOURCES    = $(wildcard generate/*.cpp)
INSTR_SOURCES       = $(wildcard instr/*.cpp)
LOAD_SOURCES        = $(wildcard load/*.cpp)
ifeq (aarch64,$(P_ARCH))
	LOAD_SOURCES += load/bootstrap-aarch64.S
else ifeq (x86_64,$(P_ARCH))
	LOAD_SOURCES += load/bootstrap-x86_64.s
else ifeq (arm,$(P_ARCH))
	LOAD_SOURCES += load/bootstrap-arm.s
endif
LOG_SOURCES         = $(wildcard log/*.cpp)
OPERATION_SOURCES   = $(wildcard operation/*.cpp)
PASS_SOURCES        = $(wildcard pass/*.cpp)
RUNTIME_SOURCES     = $(wildcard runtime/*.cpp)
TRANSFORM_SOURCES   = $(wildcard transform/*.cpp)
UTIL_SOURCES        = $(wildcard util/*.c util/*.cpp)
CMINUS_SOURCES      = $(wildcard cminus/*.c)
SNIPPET_SOURCES     = $(wildcard snippet/*.c snippet/*.cpp)
ifeq (aarch64,$(P_ARCH))
	SNIPPET_SOURCES += snippet/start2-aarch64.S snippet/hook-aarch64.S
else ifeq (x86_64,$(P_ARCH))
	SNIPPET_SOURCES += snippet/start2-x86_64.S snippet/ifunc-x86_64.S \
		snippet/hook-x86_64.S
endif

exe-filename = $(foreach s,$1,$(BUILDDIR)$(dir $s)$(basename $(notdir $s)))
obj-filename = $(foreach s,$1,$(BUILDDIR)$(dir $s)$(basename $(notdir $s)).o)
dep-filename = $(foreach s,$1,$(BUILDDIR)$(dir $s)$(basename $(notdir $s)).d)

TYPICAL_SOURCES = $(CHUNK_SOURCES) $(ELF_SOURCES) $(TRANSFORM_SOURCES) \
		$(LOG_SOURCES) $(PASS_SOURCES) $(DISASM_SOURCES) $(CONDUCTOR_SOURCES) \
		$(ANALYSIS_SOURCES) $(CMINUS_SOURCES) $(GENERATE_SOURCES) $(INSTR_SOURCES) \
		$(OPERATION_SOURCES) $(DWARF_SOURCES) $(ARCHIVE_SOURCES) $(UTIL_SOURCES) \
		$(SNIPPET_SOURCES) $(RUNTIME_SOURCES) load/emulator.cpp load/segmap.cpp \
		load/callinit.cpp
TYPICAL_OBJECTS = $(call obj-filename,$(TYPICAL_SOURCES))
LOADER_SOURCES = $(TYPICAL_SOURCES) $(BREAK_SOURCES) $(LOAD_SOURCES)
LOADER_OBJECTS = $(call obj-filename,$(LOADER_SOURCES))
LOADERPIE_SOURCES = $(LOAD_SOURCES)
LOADERPIE_OBJECTS = $(call obj-filename,$(LOADERPIE_SOURCES))
ADDON_SOURCES = $(SNIPPET_SOURCES)
ADDON_OBJECTS = $(call obj-filename,$(ADDON_SOURCES))
ALL_SOURCES = $(sort $(LOADER_SOURCES) $(BINLOADER_SOURCES))
ALL_OBJECTS = $(call obj-filename,$(ALL_SOURCES))

ifneq ("$(filter x86_64,$(P_ARCH))","")
DISTORM_A = ../dep/distorm3/distorm3.a
DISTORM_SO = -L ../dep/distorm3/make/linux/ -ldistorm3 -Wl,-rpath,$(abspath ../dep/distorm3/make/linux)
endif

BUILDTREE = $(sort $(dir $(ALL_OBJECTS)))

LOADER = $(BUILDDIR)loader
LIBRARY = $(BUILDDIR)libegalito.a
SHARED_LIBRARY = $(BUILDDIR)libegalito.so
ADDON_LIBRARY = $(BUILDDIR)libaddon.so
LOADERPIE = $(BUILDDIR)loader-pie

OUTPUTS = $(LOADER) $(BINLOADER) $(LIBRARY) $(SHARED_LIBRARY) \
		$(ADDON_LIBRARY)
SYMLINKS = $(notdir $(OUTPUTS))

GEN_TIMESTAMP = $(BUILDDIR).gen_timestamp

# Default target
.PHONY: all
all: $(GEN_TIMESTAMP) $(OUTPUTS) .symlinks
	@true

release: GENERIC_FLAGS += -DRELEASE_BUILD -DNDEBUG -Wno-unused-but-set-variable -Wno-unused-variable -Wno-empty-body
release: all
	@true

$(BUILDDIR)load/emulator.o $(BUILDDIR)transform/data.o: | $(GEN_TIMESTAMP)
$(ALL_OBJECTS): | $(BUILDTREE)
$(BUILDTREE): ../config/config.h
	@mkdir -p $@

../config/config.h:
	$(call short-make,../config)

.symlinks: $(OUTPUTS)
	@touch $@
	@echo "LN-S" $(OUTPUTS)
	@if [ "$(P_ARCH)" != "`cat $@`" ]; then \
		echo $(P_ARCH) > $@; \
		ln -sf $(BUILDDIR)loader; \
		ln -sf $(BUILDDIR)libegalito.a; \
		ln -sf $(BUILDDIR)libegalito.so; \
		ln -sf $(BUILDDIR)libaddon.so; \
		rm -f example; \
		ln -s ../test/example example; \
		rm -f ex; \
		ln -s ../test/example/$(BUILDDIR) ex; \
	fi

$(GEN_TIMESTAMP): $(BUILDTREE)
	@touch $@

# Dependencies
DEPEND_FILES = $(call dep-filename,$(ALL_SOURCES))
-include $(DEPEND_FILES)

# Special files
$(BUILDDIR)load/usage.o: load/usage.cpp load/usage.h
	$(SHORT_CXX) $(CXXFLAGS) $(DEPFLAGS) -DGIT_VERSION=$(shell git rev-parse --short HEAD) -c -o $@ $<
$(BUILDDIR)elf/sharedlib.o: elf/sharedlib.cpp
	$(SHORT_CXX) $(CXXFLAGS) $(DEPFLAGS) -DDEBUG_GROUP=$(shell echo $< | perl -ne 'm|^(\w+)/|g;print lc($$1)') '-DLIBC_PATH="$(shell /usr/bin/ldd /bin/ls | grep libc.so | awk '{ print $$3 }')"' -c -o $@ $<

# Programs and libraries
$(LOADER): $(LOADER_OBJECTS)
	$(SHORT_LINK) -static -o $@ -pg \
		-nostartfiles $(STARTFILES) $^ $(CLDFLAGS) $(ENDFILES) -Wl,--eh-frame-hdr \
		-Wl,-Ttext-segment=0x60000000 $(DISTORM_A) -lpthread
$(LIBRARY): $(TYPICAL_OBJECTS)
	$(SHORT_AR) cr $(LIBRARY) $(TYPICAL_OBJECTS) $(DISTORM_A)
$(SHARED_LIBRARY): $(TYPICAL_OBJECTS:.o=.so)
	$(SHORT_LINK) -shared -fPIC -Wl,-soname,libegalito.so -Wl,--no-undefined $^ $(CLDFLAGS) -o $@ $(DISTORM_SO) -lpthread
$(ADDON_LIBRARY): $(ADDON_OBJECTS:.o=.so)
	$(SHORT_LINK) -nostdlib -shared -fPIC -Wl,-soname,libaddon.so $^ -o $@
$(LOADERPIE): $(LOADERPIE_OBJECTS) | $(SHARED_LIBRARY)
	$(SHORT_LINK) $(CXXFLAGS) -o $@ /usr/lib64/crti.o /usr/lib64/gcc/x86_64-suse-linux/7/crtbegin.o $^ $(CLDFLAGS) -nostartfiles -L$(BUILDDIR) -Wl,-rpath=$(abspath .) -legalito $(DISTORM_SO) /usr/lib64/gcc/x86_64-suse-linux/7/crtend.o /usr/lib64/crtn.o

# Other targets
.PHONY: clean
clean:
	-rm -rf $(BUILDDIR) .symlinks $(SYMLINKS) ex example symbols.elf
