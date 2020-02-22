# Makefile for egalito applications

include ../env.mk

# Dependencies for Python Bindings
BOOST_PYTHON_LIB = boost_python3
PYTHON_LIB = python3.6m
PYTHON_INC_DIR = /usr/include/python3.6m

CFLAGS      += -g -I ../src/
CXXFLAGS    += -g -I ../src/
CLDFLAGS    += -L ../src/$(BUILDDIR) -legalito \
	-Wl,-rpath=$(abspath ../src/$(BUILDDIR)) \
	-Wl,-rpath=$(abspath ../dep/capstone/install/lib)

ELF_SOURCES             = $(wildcard elf/*.cpp)
SANDBOX_SOURCES         = $(wildcard sandbox/*.c sandbox/*.cpp)
SANDBOX_INJECT_SOURCES  = $(wildcard sandbox/inject/*.c sandbox/inject/*.cpp)
COVERAGE_SOURCES        = $(wildcard coverage/*.c coverage/*.cpp)
COVERAGE_INJECT_SOURCES = $(wildcard coverage/inject/*.c coverage/inject/*.s)
HARDEN_SOURCES          = $(wildcard harden/*.cpp)
CET_INJECT_SOURCES      = $(wildcard cet/inject/*.c cet/inject/*.cpp)
SHELL_SOURCES           = $(wildcard shell/*.cpp)
SHELL2_SOURCES          = $(wildcard shell2/*.cpp)
OBJDUMP_SOURCES         = $(wildcard objdump/*.cpp)
ORDER_SOURCES           = $(wildcard order/*.cpp)
PROFILE_SOURCES         = $(wildcard profile/*.cpp)
PYTHON_SOURCES          = $(wildcard python/*.cpp)
TWOCODE_SOURCES         = $(wildcard twocode/*.cpp)

exe-filename = $(foreach s,$1,$(BUILDDIR)$(dir $s)$(basename $(notdir $s)))
obj-filename = $(foreach s,$1,$(BUILDDIR)$(dir $s)$(basename $(notdir $s)).o)
dep-filename = $(foreach s,$1,$(BUILDDIR)$(dir $s)$(basename $(notdir $s)).d)

ETSHELL_SOURCES = $(SHELL_SOURCES)
ETSHELL_OBJECTS = $(call obj-filename,$(ETSHELL_SOURCES))
ETSHELL2_SOURCES = $(SHELL2_SOURCES)
ETSHELL2_OBJECTS = $(call obj-filename,$(ETSHELL2_SOURCES))
ETOBJDUMP_SOURCES = $(OBJDUMP_SOURCES)
ETOBJDUMP_OBJECTS = $(call obj-filename,$(ETOBJDUMP_SOURCES))
ETSANDBOX_SOURCES = $(SANDBOX_SOURCES)
ETSANDBOX_OBJECTS = $(call obj-filename,$(ETSANDBOX_SOURCES))
ETCOVERAGE_SOURCES = $(COVERAGE_SOURCES)
ETCOVERAGE_OBJECTS = $(call obj-filename,$(ETCOVERAGE_SOURCES))
ETHARDEN_SOURCES = $(HARDEN_SOURCES)
ETHARDEN_OBJECTS = $(call obj-filename,$(ETHARDEN_SOURCES))
LIBSANDBOX_SOURCES = $(SANDBOX_INJECT_SOURCES)
LIBSANDBOX_OBJECTS = $(call obj-filename,$(LIBSANDBOX_SOURCES))
LIBCOVERAGE_SOURCES = $(COVERAGE_INJECT_SOURCES)
LIBCOVERAGE_OBJECTS = $(call obj-filename,$(LIBCOVERAGE_SOURCES))
LIBCET_SOURCES = $(CET_INJECT_SOURCES)
LIBCET_OBJECTS = $(call obj-filename,$(LIBCET_SOURCES))
ETELF_SOURCES = $(ELF_SOURCES)
ETELF_OBJECTS = $(call obj-filename,$(ETELF_SOURCES))
ETPROFILE_SOURCES = $(PROFILE_SOURCES)
ETPROFILE_OBJECTS = $(call obj-filename,$(ETPROFILE_SOURCES))
ETTWOCODE_SOURCES = $(TWOCODE_SOURCES)
ETTWOCODE_OBJECTS = $(call obj-filename,$(ETTWOCODE_SOURCES))
ETORDER_SOURCES = $(ORDER_SOURCES)
ETORDER_OBJECTS = $(call obj-filename,$(ETORDER_SOURCES))

ALL_SOURCES = $(sort $(ETSHELL_SOURCES) $(ETSHELL2_SOURCES) $(ETOBJDUMP_SOURCES) \
    $(ETSANDBOX_SOURCES) $(LIBSANDBOX_SOURCES) \
    $(ETCOVERAGE_SOURCES) $(LIBCOVERAGE_SOURCES) \
    $(ETHARDEN_SOURCES) $(LIBCET_SOURCES) \
    $(ETELF_SOURCES) $(ETPROFILE_SOURCES) $(ETTWOCODE_SOURCES) $(ETORDER_SOURCES))
ALL_OBJECTS = $(call obj-filename,$(ALL_SOURCES))

PYTHON_OBJECTS = $(call obj-filename,$(PYTHON_SOURCES))
BUILDTREE = $(sort $(dir $(ALL_OBJECTS) $(PYTHON_OBJECTS)))

ETSHELL = $(BUILDDIR)etshell
ETSHELL2 = $(BUILDDIR)etshell2
ETOBJDUMP = $(BUILDDIR)etobjdump
ETSANDBOX = $(BUILDDIR)etsandbox
ETCOVERAGE = $(BUILDDIR)etcoverage
ETHARDEN = $(BUILDDIR)etharden
ETHARDEN = $(BUILDDIR)etharden
ETELF = $(BUILDDIR)etelf
ETPROFILE = $(BUILDDIR)etprofile
ETTWOCODE = $(BUILDDIR)ettwocode
ETORDER = $(BUILDDIR)etorder
PYTHON_BINDING = $(BUILDDIR)python_egalito.so
PYSHELL = $(BUILDDIR)pyshell
SANDBOX_LIBRARY = $(BUILDDIR)libsandbox.so
COVERAGE_LIBRARY = $(BUILDDIR)libcoverage.so
CET_LIBRARY = $(BUILDDIR)libcet.so

OUTPUTS = $(ETSHELL) $(ETSHELL2) $(ETOBJDUMP) $(ETSANDBOX) $(SANDBOX_LIBRARY) $(ETCOVERAGE) $(COVERAGE_LIBRARY) $(ETHARDEN) $(CET_LIBRARY) $(ETELF) $(ETPROFILE) $(ETTWOCODE) $(ETORDER)

# Default target
.PHONY: all
all: app-all .symlinks
	@true

app-all: $(OUTPUTS) | rebuild-src

python: $(BUILDTREE) $(PYTHON_BINDING) $(PYSHELL)
	@ln -sf $(PYSHELL)

ifeq ($(findstring clean,$(MAKECMDGOALS)),)
Makefile: rebuild-src
endif

$(ALL_OBJECTS): | $(BUILDTREE)
$(BUILDTREE): ../config/config.h
	@mkdir -p $@

../config/config.h:
	$(call short-make,../config)

.symlinks: $(OUTPUTS)
	@touch .symlinks
	@echo "LN-S" $(OUTPUTS)
	@ln -sf $(ETSHELL)
	@ln -sf $(ETSHELL2)
	@ln -sf $(ETOBJDUMP)
	@ln -sf $(ETSANDBOX)
	@ln -sf $(SANDBOX_LIBRARY)
	@ln -sf $(ETCOVERAGE)
	@ln -sf $(COVERAGE_LIBRARY)
	@ln -sf $(ETHARDEN)
	@ln -sf $(CET_LIBRARY)
	@ln -sf $(ETELF)
	@ln -sf $(ETPROFILE)
	@ln -sf $(ETTWOCODE)
	@ln -sf $(ETORDER)
	@ln -sf $(shell pwd)/../src/$(BUILDDIR)libegalito.so $(BUILDDIR)libegalito.so

.PHONY: rebuild-src
rebuild-src:
	$(call short-make,../src)

# Dependencies
DEPEND_FILES = $(call dep-filename,$(ALL_SOURCES))
-include $(DEPEND_FILES)

# Special files
$(BUILDDIR)python/%.o: python/%.cpp
	$(SHORT_CXX) $(CXXFLAGS) -I $(PYTHON_INC_DIR) -fPIC $(DEPFLAGS) -c -o $@ $<

$(BUILDDIR)shell/shell.o: shell/shell.cpp
	$(SHORT_CXX) $(CXXFLAGS) $(DEPFLAGS) -DGIT_VERSION=$(shell git rev-parse --short HEAD) -c -o $@ $<
$(BUILDDIR)shell2/shell.o: shell2/shell.cpp
	$(SHORT_CXX) $(CXXFLAGS) $(DEPFLAGS) -DGIT_VERSION=$(shell git rev-parse --short HEAD) -c -o $@ $<

$(PYTHON_BINDING): $(PYTHON_OBJECTS) ../src/$(BUILDDIR)libegalito.a
	$(SHORT_CXX) $(CXXFLAGS) -fPIC -o $@ $< -l$(BOOST_PYTHON_LIB) -l$(PYTHON_LIB)  $(CLDFLAGS) -shared

# Programs and libraries
$(ETSHELL): $(ETSHELL_OBJECTS)
	$(SHORT_LINK) $(CXXFLAGS) -o $@ $^ $(CLDFLAGS) -lreadline -Wl,-rpath=$(abspath ../src)
$(ETSHELL): ../src/$(BUILDDIR)libegalito.so

$(ETSHELL2): $(ETSHELL2_OBJECTS)
	$(SHORT_LINK) $(CXXFLAGS) -o $@ $^ $(CLDFLAGS) -lreadline -Wl,-rpath=$(abspath ../src)
$(ETSHELL2): ../src/$(BUILDDIR)libegalito.so

$(ETOBJDUMP): $(ETOBJDUMP_OBJECTS)
	$(SHORT_LINK) $(CXXFLAGS) -o $@ $^ $(CLDFLAGS) -Wl,-rpath=$(abspath ../src)
$(ETOBJDUMP): ../src/$(BUILDDIR)libegalito.so

$(ETSANDBOX): $(ETSANDBOX_OBJECTS)
	$(SHORT_LINK) $(CXXFLAGS) -o $@ $^ $(CLDFLAGS) -Wl,-rpath=$(abspath ../src)
$(ETSANDBOX): ../src/$(BUILDDIR)libegalito.so

$(ETCOVERAGE): $(ETCOVERAGE_OBJECTS)
	$(SHORT_LINK) $(CXXFLAGS) -o $@ $^ $(CLDFLAGS) -Wl,-rpath=$(abspath ../src)
$(ETCOVERAGE): ../src/$(BUILDDIR)libegalito.so

$(ETHARDEN): $(ETHARDEN_OBJECTS)
	$(SHORT_LINK) $(CXXFLAGS) -o $@ $^ $(CLDFLAGS) -Wl,-rpath=$(abspath ../src)
$(ETHARDEN): ../src/$(BUILDDIR)libegalito.so

$(ETELF): $(ETELF_OBJECTS)
	$(SHORT_LINK) $(CXXFLAGS) -o $@ $^ $(CLDFLAGS) -Wl,-rpath=$(abspath ../src)
$(ETELF): ../src/$(BUILDDIR)libegalito.so

$(ETPROFILE): $(ETPROFILE_OBJECTS)
	$(SHORT_LINK) $(CXXFLAGS) -o $@ $^ $(CLDFLAGS) -Wl,-rpath=$(abspath ../src)
$(ETPROFILE): ../src/$(BUILDDIR)libegalito.so

$(ETTWOCODE): $(ETTWOCODE_OBJECTS)
	$(SHORT_LINK) $(CXXFLAGS) -o $@ $^ $(CLDFLAGS) -Wl,-rpath=$(abspath ../src)
$(ETTWOCODE): ../src/$(BUILDDIR)libegalito.so

$(ETORDER): $(ETORDER_OBJECTS)
	$(SHORT_LINK) $(CXXFLAGS) -o $@ $^ $(CLDFLAGS) -Wl,-rpath=$(abspath ../src)
$(ETORDER): ../src/$(BUILDDIR)libegalito.so

$(PYSHELL): $(PYTHON_BINDING) python/shell.py
	cp python/shell.py $(BUILDDIR)pyshell
	chmod +x $(BUILDDIR)pyshell

$(BUILDDIR)sandbox/inject/%.o: sandbox/inject/%.c
	$(SHORT_CC) $(CCFLAGS) -fPIC $(DEPFLAGS) -c -o $@ $<
$(SANDBOX_LIBRARY): $(LIBSANDBOX_OBJECTS)
	$(SHORT_LINK) -shared -fPIC -Wl,-soname,libsandbox.so $^ -o $@

$(BUILDDIR)coverage/inject/%.o: coverage/inject/%.c
	$(SHORT_CC) $(CCFLAGS) -fPIC $(DEPFLAGS) -c -o $@ $<
$(COVERAGE_LIBRARY): $(LIBCOVERAGE_OBJECTS)
	$(SHORT_LINK) -shared -fPIC -Wl,-soname,libcoverage.so $^ -o $@

$(BUILDDIR)cet/inject/%.o: cet/inject/%.c
	$(SHORT_CC) $(CCFLAGS) -fPIC $(DEPFLAGS) -c -o $@ $<
$(CET_LIBRARY): $(LIBCET_OBJECTS)
	$(SHORT_LINK) -shared -fPIC -Wl,-soname,libcet.so $^ -o $@

# Other targets
.PHONY: clean realclean
clean:
	-rm -rf $(BUILDDIR) .symlinks etshell etshell2 pyshell etobjdump etsandbox libsandbox.so etcoverage libcoverage.so etharden libcet.so etelf etprofile ettwocode etorder
